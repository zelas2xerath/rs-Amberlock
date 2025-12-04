use amberlock_winsec as winsec;

#[derive(Debug, Clone)]
pub struct InspectReport {
    pub capability: amberlock_types::Capability,
}

pub fn probe_capability() -> anyhow::Result<InspectReport> {
    let p = winsec::probe_capability()?;
    Ok(InspectReport {
        capability: amberlock_types::Capability {
            caller_il: p.caller_il,
            can_touch_sacl: p.has_se_security,
            can_set_system: p.has_se_relabel,
        },
    })
}
