use crate::errors::{CoreError, Result};
use amberlock_storage::NdjsonWriter;
use amberlock_types::*;
use amberlock_winsec as winsec;
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct BatchOptions {
    pub desired_level: LabelLevel,
    pub mode: ProtectMode,
    pub policy: MandPolicy, // 默认仅 NW；NR/NX 作为尝试位
    pub parallelism: usize,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BatchResult {
    pub total: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub downgraded: u64, // 期望 System 实际 High 等
}

fn now_iso8601() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn file_kind(p: &Path) -> TargetKind {
    if p.is_dir() {
        TargetKind::Directory
    } else {
        TargetKind::File
    }
}

pub fn batch_lock(
    paths: &[PathBuf],
    opts: &BatchOptions,
    logger: &NdjsonWriter,
) -> Result<BatchResult> {
    let cap = winsec::probe_capability()?;
    let eff_level = winsec::compute_effective_level(opts.desired_level, cap.has_se_relabel);
    let user_sid = winsec::read_user_sid().unwrap_or_default();

    let result = paths
        .par_iter()
        .with_max_len(1) // 控制任务粒度
        .map(|p| {
            let id = Uuid::new_v4().to_string();
            let path = p.to_string_lossy().to_string();

            let before = winsec::get_object_label(&path).ok();
            let mut rec = LockRecord {
                id,
                path: path.clone(),
                kind: file_kind(p),
                mode: opts.mode,
                level_applied: eff_level,
                policy: opts.policy,
                time_utc: now_iso8601(),
                user_sid: user_sid.clone(),
                owner_before: None,
                sddl_before: before.as_ref().map(|s| s.sddl.clone()),
                sddl_after: None,
                status: "pending".into(),
                errors: vec![],
            };

            let r = if opts.dry_run {
                Ok(())
            } else {
                winsec::set_mandatory_label(&path, eff_level, opts.policy)
            };

            match r {
                Ok(_) => {
                    let after = winsec::get_object_label(&path).ok();
                    rec.sddl_after = after.as_ref().map(|s| s.sddl.clone());
                    rec.status = "success".into();
                    logger.write_record(&rec).ok();
                    Ok::<(), CoreError>(())
                }
                Err(e) => {
                    rec.status = "error".into();
                    rec.errors.push(format!("{e:?}"));
                    logger.write_record(&rec).ok();
                    Err(CoreError::from(e))
                }
            }
        })
        .collect::<Vec<_>>();

    let mut br = BatchResult::default();
    br.total = result.len() as u64;
    for r in result {
        match r {
            Ok(_) => br.succeeded += 1,
            Err(_) => br.failed += 1,
        }
    }
    Ok(br)
}

pub fn batch_unlock(
    paths: &[PathBuf],
    password: &str,
    vault_blob: &[u8],
    logger: &NdjsonWriter,
) -> Result<BatchResult> {
    if !amberlock_auth::verify_password(vault_blob, password).map_err(|_| CoreError::AuthFailed)? {
        return Err(CoreError::AuthFailed);
    }
    let opts = BatchOptions {
        desired_level: LabelLevel::Medium,
        mode: ProtectMode::ReadOnly,
        policy: MandPolicy::NW,
        parallelism: 4,
        dry_run: false,
    };
    // 逻辑：移除 ML 或降级为 Medium（这里采用移除）
    let res = paths
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .map(|path| {
            let id = Uuid::new_v4().to_string();
            let before = winsec::get_object_label(&path).ok();
            let r = winsec::remove_mandatory_label(&path);
            let mut rec = LockRecord {
                id,
                path: path.clone(),
                kind: file_kind(Path::new(&path)),
                mode: opts.mode,
                level_applied: LabelLevel::Medium,
                policy: opts.policy,
                time_utc: now_iso8601(),
                user_sid: winsec::read_user_sid().unwrap_or_default(),
                owner_before: None,
                sddl_before: before.as_ref().map(|s| s.sddl.clone()),
                sddl_after: None,
                status: String::new(),
                errors: vec![],
            };
            match r {
                Ok(_) => {
                    rec.status = "success".into();
                    logger.write_record(&rec).ok();
                    Ok::<(), CoreError>(())
                }
                Err(e) => {
                    rec.status = "error".into();
                    rec.errors.push(format!("{e:?}"));
                    logger.write_record(&rec).ok();
                    Err(CoreError::from(e))
                }
            }
        })
        .collect::<Vec<_>>();

    let mut br = BatchResult::default();
    br.total = res.len() as u64;
    for r in res {
        if r.is_ok() {
            br.succeeded += 1
        } else {
            br.failed += 1
        }
    }
    Ok(br)
}
