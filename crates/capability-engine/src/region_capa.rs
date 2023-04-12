use crate::domain::{Domain, DomainPool, LocalCapa};
use crate::gen_arena::{GenArena, Handle};
use crate::region::{AccessRights, PermissionChange};
use crate::update::{Update, UpdateBuffer};
use crate::{CapaError, N};

pub struct RegionCapa {
    domain: Handle<Domain>,
    left: Option<Handle<RegionCapa>>,
    right: Option<Handle<RegionCapa>>,
    is_active: bool,
    is_confidential: bool,
    pub(crate) access: AccessRights,
}

impl RegionCapa {
    /// Returns an invalid region capability.
    pub const fn new_invalid() -> Self {
        Self {
            domain: Handle::new_invalid(),
            left: None,
            right: None,
            is_active: false,
            is_confidential: false,
            access: AccessRights { start: 0, end: 0 },
        }
    }

    pub fn new(domain: Handle<Domain>, access: AccessRights) -> Self {
        Self {
            domain,
            left: None,
            right: None,
            is_active: true,
            is_confidential: false,
            access,
        }
    }

    /// Set as confidential.
    pub fn confidential(mut self) -> Self {
        self.is_confidential = true;
        self
    }

    /// Update the confidential attripute.
    pub fn set_confidential(mut self, confidential: bool) -> Self {
        self.is_confidential = confidential;
        self
    }
}

pub type CapaHandle = Handle<RegionCapa>;
pub type CapaPool = GenArena<RegionCapa, N>;

pub fn restore(
    handle: Handle<RegionCapa>,
    regions: &mut CapaPool,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
) -> Result<(), CapaError> {
    log::trace!("Restoring {:?}", handle);

    let capa = &mut regions[handle];
    let domain = capa.domain;
    let right = capa.right;
    let left = capa.left;

    capa.is_active = true;
    apply_install(capa, domain, domains, updates)?;

    if let Some(right) = right {
        revoke(right, regions, domains, updates)?;
    }
    if let Some(left) = left {
        revoke(left, regions, domains, updates)?;
    }

    let capa = &mut regions[handle];
    capa.left = None;
    capa.right = None;

    Ok(())
}

pub(crate) fn revoke(
    handle: CapaHandle,
    regions: &mut CapaPool,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
) -> Result<(), CapaError> {
    log::trace!("Revoking {:?}", handle);

    let capa = &mut regions[handle];
    let domain = capa.domain;
    let right = capa.right;
    let left = capa.left;

    apply_uninstall(capa, domain, domains, updates)?;
    regions.free(handle);

    if let Some(right) = right {
        revoke(right, regions, domains, updates)?;
    }
    if let Some(left) = left {
        revoke(left, regions, domains, updates)?;
    }

    Ok(())
}

pub fn duplicate(
    handle: Handle<RegionCapa>,
    regions: &mut CapaPool,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
    access_left: AccessRights,
    access_right: AccessRights,
) -> Result<(LocalCapa, LocalCapa), CapaError> {
    log::trace!("Duplicating {:?}", handle);

    let capa = &regions[handle];
    let domain_handle = capa.domain;

    // Ensure that the operation is valid
    if capa.left.is_some() || capa.right.is_some() {
        log::info!("Tried to duplicate a handle with a left and/or right child");
        return Err(CapaError::CannotDuplicate);
    }
    if !is_valid_duplicate(&capa, access_left, access_right) {
        log::info!("Invalid duplicate");
        return Err(CapaError::InvalidDuplicate);
    }

    // Mark them as confidential if appropriate
    let is_confidential = capa.is_confidential && !overlap(access_left, access_right);

    // Allocate the two region capas
    let Some(left) = regions.allocate(
        RegionCapa::new(domain_handle, access_left)
            .set_confidential(is_confidential)
    ) else {
        log::info!("Ouf of memory during left allocation on duplicate");
        return Err(CapaError::OutOfMemory);
    };
    let Some(right) = regions.allocate(
        RegionCapa::new(domain_handle, access_right)
            .set_confidential(is_confidential)
    ) else {
        log::info!("Ouf of memory during right allocation on duplicate");
        // Cleanup previous allocation
        regions.free(left);
        return Err(CapaError::OutOfMemory);
    };

    // Insert the capas in the domain
    let domain = &mut domains[domain_handle];
    let Ok(capa_left) = domain.insert_capa(left) else {
        log::info!("Failed to insert left capa in domain");
        // Cleanup previous allocatons
        regions.free(left);
        regions.free(right);
        return Err(CapaError::OutOfMemory);
    };
    let Ok(capa_right) = domain.insert_capa(right) else {
        log::info!("Failed to insert right capa in domain");
        // Cleanup previous allocatons
        regions.free(left);
        regions.free(right);
        return Err(CapaError::OutOfMemory);
    };

    let capa = &mut regions[handle];
    capa.left = Some(left);
    capa.right = Some(right);

    // TODO: can be optimized in some cases (e.g. the two new regions cover the exact same memory)
    apply_install(&regions[left], domain_handle, domains, updates)?;
    apply_install(&regions[right], domain_handle, domains, updates)?;
    apply_uninstall(&regions[handle], domain_handle, domains, updates)?;

    // Deactivate capa
    regions[handle].is_active = false;

    Ok((capa_left, capa_right))
}

pub fn send(
    handle: Handle<RegionCapa>,
    regions: &mut CapaPool,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
    domain: Handle<Domain>,
) -> Result<(), CapaError> {
    log::trace!("Sending region {:?}", handle);

    let capa = &mut regions[handle];
    let old_domain = capa.domain;
    capa.domain = domain;

    apply_uninstall(capa, old_domain, domains, updates)?;
    apply_install(capa, domain, domains, updates)?;

    Ok(())
}

pub fn install(
    handle: CapaHandle,
    domain: Handle<Domain>,
    regions: &mut CapaPool,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
) -> Result<LocalCapa, CapaError> {
    log::trace!("Installing {:?}", handle);

    let capa = &mut regions[handle];

    if capa.domain != domain {
        log::error!("tried a region capability with a different domain");
        return Err(CapaError::InvalidInstall);
    }

    let local_capa = domains[domain].insert_capa(handle)?;
    apply_install(capa, domain, domains, updates)?;

    Ok(local_capa)
}

fn apply_install(
    capa: &RegionCapa,
    domain_handle: Handle<Domain>,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
) -> Result<(), CapaError> {
    if !capa.is_active {
        return Ok(());
    }

    if let Some(domain) = domains.get_mut(domain_handle) {
        let change = domain.activate_region(capa.access)?;
        if let PermissionChange::Some = change {
            updates.push(Update::PermissionUpdate {
                domain: domain_handle,
            });
        }
    }

    Ok(())
}

fn apply_uninstall(
    capa: &RegionCapa,
    domain_handle: Handle<Domain>,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
) -> Result<(), CapaError> {
    if !capa.is_active {
        return Ok(());
    }

    if let Some(domain) = domains.get_mut(domain_handle) {
        let change = domain.deactivate_region(capa.access)?;
        if let PermissionChange::Some = change {
            updates.push(Update::PermissionUpdate {
                domain: domain_handle,
            });
        }
    }

    Ok(())
}

fn is_valid_duplicate(region: &RegionCapa, left: AccessRights, right: AccessRights) -> bool {
    contains(region, left) && contains(region, right)
}

fn contains(region: &RegionCapa, access: AccessRights) -> bool {
    region.access.start <= access.start && region.access.end >= access.end
}

fn overlap(left: AccessRights, right: AccessRights) -> bool {
    left.start < right.end && left.end > right.start
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_overlap() {
        assert!(overlap(
            AccessRights { start: 2, end: 3 },
            AccessRights { start: 1, end: 4 }
        ));
        assert!(overlap(
            AccessRights { start: 1, end: 4 },
            AccessRights { start: 2, end: 3 }
        ));
        assert!(overlap(
            AccessRights { start: 1, end: 3 },
            AccessRights { start: 2, end: 4 }
        ));
        assert!(overlap(
            AccessRights { start: 2, end: 4 },
            AccessRights { start: 1, end: 3 }
        ));
        assert!(!overlap(
            AccessRights { start: 1, end: 3 },
            AccessRights { start: 4, end: 6 }
        ));
        assert!(!overlap(
            AccessRights { start: 4, end: 6 },
            AccessRights { start: 1, end: 3 }
        ));
    }
}
