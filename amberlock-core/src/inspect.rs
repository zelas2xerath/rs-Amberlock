use amberlock_winsec as winsec;
use amberlock_types::Capability;

#[derive(Debug, Clone)]
pub struct InspectReport {
    pub capability: Capability,
}

pub fn probe_capability() -> anyhow::Result<InspectReport> {
    let p = winsec::token::probe_capability()?;
    Ok(InspectReport {
        capability: Capability {
            caller_il: p.caller_il,
            can_touch_sacl: p.has_se_security,
            can_set_system: p.has_se_relabel,
        },
    })
}
