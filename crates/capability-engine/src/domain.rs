use crate::capa::{Capa, IntoCapa};
use crate::config::{NB_CAPAS_PER_DOMAIN, NB_DOMAINS};
use crate::context::{Context, ContextPool};
use crate::free_list::FreeList;
use crate::gen_arena::GenArena;
use crate::region::{PermissionChange, RegionTracker};
use crate::update::{Update, UpdateBuffer};
use crate::utils::BitmapIterator;
use crate::{region_capa, AccessRights, CapaError, Handle, RegionPool};

pub type DomainHandle = Handle<Domain>;
pub(crate) type DomainPool = GenArena<Domain, NB_DOMAINS>;

// —————————————————————————————— Permissions ——————————————————————————————— //

#[rustfmt::skip]
pub mod permission {
    pub const SPAWN:     u64 = 1 << 0;
    pub const SEND:      u64 = 1 << 1;
    pub const DUPLICATE: u64 = 1 << 2;

    /// All possible permissions
    pub const ALL:  u64 = SPAWN | SEND | DUPLICATE;
    /// None of the existing permissions
    pub const NONE: u64 = 0;
}

// —————————————————————————— Domain Capabilities ——————————————————————————— //

/// An index into the capability table of a domain.
#[derive(Debug, Clone, Copy)]
pub struct LocalCapa {
    idx: usize,
}

impl LocalCapa {
    pub fn as_usize(self) -> usize {
        self.idx
    }

    pub fn as_u64(self) -> u64 {
        self.idx as u64
    }

    pub fn new(idx: usize) -> Self {
        Self { idx }
    }
}

/// A token used to iterate capabilites of a domain.
#[derive(Clone, Copy)]
pub struct NextCapaToken {
    idx: usize,
}

impl NextCapaToken {
    pub fn new() -> Self {
        Self { idx: 0 }
    }

    pub fn from_usize(idx: usize) -> Self {
        Self { idx }
    }

    pub fn as_usize(self) -> usize {
        self.idx
    }

    pub fn as_u64(self) -> u64 {
        self.idx as u64
    }
}

// ————————————————————————————————— Domain ————————————————————————————————— //

pub struct Domain {
    /// Unique domain ID.
    id: usize,
    /// Domain capabilities.
    capas: [Capa; NB_CAPAS_PER_DOMAIN],
    /// Free list of capabilities, used for allocating new capabilities.
    free_list: FreeList<NB_CAPAS_PER_DOMAIN>,
    /// Tracker for region permissions.
    regions: RegionTracker,
    /// The (optional) manager of this domain.
    manager: Option<Handle<Domain>>,
    /// A bitmap of permissions.
    permissions: u64,
    /// A bitmap of interrupts and exception the domain can handle.
    interrupts: u64,
    /// A bitmap of cores the domain is runing on.
    cores: u64,
    /// Is this domain in the process of being revoked?
    is_being_revoked: bool,
    /// Is the domain sealed?
    is_sealed: bool,
}

impl Domain {
    pub const fn new(id: usize) -> Self {
        const INVALID_CAPA: Capa = Capa::None;

        Self {
            id,
            capas: [INVALID_CAPA; NB_CAPAS_PER_DOMAIN],
            free_list: FreeList::new(),
            regions: RegionTracker::new(),
            manager: None,
            permissions: permission::NONE,
            interrupts: 0,
            cores: 0,
            is_being_revoked: false,
            is_sealed: false,
        }
    }

    pub(crate) fn set_manager(&mut self, manager: Handle<Domain>) {
        self.manager = Some(manager);
    }

    /// Get a capability from a domain.
    pub(crate) fn get(&self, index: LocalCapa) -> Result<Capa, CapaError> {
        if self.free_list.is_free(index.idx) {
            log::info!("Invalid capability index: {}", index.idx);
            return Err(CapaError::CapabilityDoesNotExist);
        }
        Ok(self.capas[index.idx])
    }

    /// Get a mutable reference to a capability from a domain.
    fn get_mut(&mut self, index: LocalCapa) -> Result<&mut Capa, CapaError> {
        if self.free_list.is_free(index.idx) {
            log::info!("Invalid capability index: {}", index.idx);
            return Err(CapaError::CapabilityDoesNotExist);
        }
        Ok(&mut self.capas[index.idx])
    }

    /// Mark the domain as executing on the given core.
    pub(crate) fn execute_on_core(&mut self, core_id: usize) {
        let core_id = 1 << core_id;
        self.cores |= core_id;
    }

    /// Remove the core from the bitmap of cores runing the domain.
    pub(crate) fn remove_from_core(&mut self, core_id: usize) {
        let core_id = 1 << core_id;
        if self.cores & core_id == 0 {
            log::error!("Removing from a core in which the domains was NOT executing");
        }
        self.cores &= !core_id
    }

    /// Emit TLB shootdown updates for all cores executing the domain.
    fn emit_shootdown(&self, updates: &mut UpdateBuffer) {
        for core in BitmapIterator::new(self.cores) {
            updates.push(Update::TlbShootdown { core })
        }
    }

    pub fn regions(&self) -> &RegionTracker {
        &self.regions
    }

    pub fn id(&self) -> usize {
        self.id
    }

    /// Returns Wether or not this domain can handle the given interrupt.
    pub fn can_handle(&self, interrupt: u64) -> bool {
        self.interrupts & interrupt != 0 && self.is_sealed
    }

    pub fn seal(&mut self) -> Result<(), CapaError> {
        if self.is_sealed {
            Err(CapaError::AlreadySealed)
        } else {
            self.is_sealed = true;
            Ok(())
        }
    }

    pub fn is_sealed(&self) -> bool {
        self.is_sealed
    }

    fn is_valid(
        &self,
        idx: usize,
        regions: &RegionPool,
        domains: &DomainPool,
        contexts: &ContextPool,
    ) -> bool {
        match self.capas[idx] {
            Capa::None => false,
            Capa::Region(handle) => regions.get(handle).is_some(),
            Capa::Management(handle) => domains.get(handle).is_some(),
            Capa::Channel(handle) => domains.get(handle).is_some(),
            Capa::Switch { to, ctx } => domains.get(to).is_some() && contexts.get(ctx).is_some(),
        }
    }
}

// —————————————————————————————— Insert Capa ——————————————————————————————— //

/// insert a capability into a domain.
pub(crate) fn insert_capa(
    domain: Handle<Domain>,
    capa: impl IntoCapa,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
    contexts: &mut ContextPool,
) -> Result<LocalCapa, CapaError> {
    // Find a free slot
    let idx = match domains[domain].free_list.allocate() {
        Some(idx) => idx,
        None => {
            // Run the garbage collection and retry
            free_invalid_capas(domain, regions, domains, contexts);
            let Some(idx) = domains[domain].free_list.allocate() else {
                    log::trace!("Could not insert capa in domain: out of memory");
                    return Err(CapaError::OutOfMemory);
                };
            idx
        }
    };

    // Insert the capa
    domains[domain].capas[idx] = capa.into_capa();
    Ok(LocalCapa { idx })
}

/// Remove a capability from a domain.
pub(crate) fn remove_capa(
    domain: Handle<Domain>,
    index: LocalCapa,
    domains: &mut DomainPool,
) -> Result<Capa, CapaError> {
    let domain = &mut domains[domain];
    let capa = domain.get(index)?;
    domain.free_list.free(index.idx);
    Ok(capa)
}

/// Run garbage collection on the domain's capabilities.
///
/// This is necessary as some capabilities are invalidated but not removed eagerly.
fn free_invalid_capas(
    domain: Handle<Domain>,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
    contexts: &mut ContextPool,
) {
    log::trace!("Runing garbage collection");
    for idx in 0..NB_CAPAS_PER_DOMAIN {
        if domains[domain].free_list.is_free(idx) {
            // Capa is already free
            continue;
        }

        // Check if capa is still valid
        let capa = domains[domain].capas[idx];
        let is_invalid = match capa {
            Capa::None => true,
            Capa::Region(h) => regions.get(h).is_none(),
            Capa::Management(h) => domains.get(h).is_none(),
            Capa::Channel(h) => domains.get(h).is_none(),
            Capa::Switch { to, ctx } => {
                let res = domains.get(to).is_none() || contexts.get(ctx).is_none();
                if res {
                    contexts.free(ctx);
                }
                res
            }
        };

        if is_invalid {
            // We checked before that the capa exists
            remove_capa(domain, LocalCapa { idx }, domains).unwrap();
        }
    }
}

// —————————————————————————————— Permissions ——————————————————————————————— //

/// Check wether a given domain has the expected subset of permissions.
pub(crate) fn has_permission(
    domain: Handle<Domain>,
    domains: &DomainPool,
    permission: u64,
) -> Result<(), CapaError> {
    if permission | permission::ALL != permission::ALL {
        // There are some undefined bits!
        return Err(CapaError::InvalidPermissions);
    }
    let domain_perms = domains[domain].permissions;
    if domain_perms & permission == permission {
        Ok(())
    } else {
        Err(CapaError::InsufficientPermissions)
    }
}

pub(crate) fn set_permissions(
    domain: Handle<Domain>,
    domains: &mut DomainPool,
    permissions: u64,
) -> Result<(), CapaError> {
    if permissions & !permission::ALL != 0 {
        return Err(CapaError::InvalidPermissions);
    }

    let domain = &mut domains[domain];
    if domain.is_sealed {
        return Err(CapaError::AlreadySealed);
    } else {
        domain.permissions = permissions;
        Ok(())
    }
}

// —————————————————————————————————— Send —————————————————————————————————— //

pub(crate) fn send_management(
    capa: Handle<Domain>,
    domains: &mut DomainPool,
    to: Handle<Domain>,
) -> Result<(), CapaError> {
    // Update manager
    domains[capa].set_manager(to);
    Ok(())
}

// ——————————————————————————————— Duplicate ———————————————————————————————— //

pub(crate) fn duplicate_capa(
    domain: Handle<Domain>,
    capa: LocalCapa,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
    contexts: &mut ContextPool,
) -> Result<LocalCapa, CapaError> {
    let capa = domains[domain].get(capa)?;

    match capa {
        // Capa that can not be duplicated
        Capa::None | Capa::Region(_) | Capa::Management(_) | Capa::Switch { .. } => {
            return Err(CapaError::CannotDuplicate);
        }
        Capa::Channel(_) => {
            // NOTE: there is no side effects when duplicating these capas
            insert_capa(domain, capa, regions, domains, contexts)
        }
    }
}

// ————————————————————————————————— Switch ————————————————————————————————— //

pub(crate) fn create_switch(
    domain: Handle<Domain>,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
    contexts: &mut ContextPool,
) -> Result<LocalCapa, CapaError> {
    let context = contexts.allocate(Context::new()).ok_or_else(|| {
        log::trace!("Unable to allocate context for switch!");
        CapaError::OutOfMemory
    })?;
    let capa = Capa::Switch {
        to: domain,
        ctx: context,
    };
    insert_capa(domain, capa, regions, domains, contexts)
}

// ———————————————————————————— Activate Region ————————————————————————————— //

pub(crate) fn activate_region(
    domain: Handle<Domain>,
    access: AccessRights,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
) -> Result<(), CapaError> {
    let dom = &mut domains[domain];

    // Drop updates on domain in the process of being revoked
    if dom.is_being_revoked {
        return Ok(());
    }

    let change = dom.regions.add_region(access.start, access.end)?;
    if let PermissionChange::Some = change {
        dom.emit_shootdown(updates);
        updates.push(Update::PermissionUpdate { domain });
    };

    Ok(())
}

pub(crate) fn deactivate_region(
    domain: Handle<Domain>,
    access: AccessRights,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
) -> Result<(), CapaError> {
    let dom = &mut domains[domain];

    // Drop updates on domain in the process of being revoked
    if dom.is_being_revoked {
        return Ok(());
    }

    let change = dom.regions.remove_region(access.start, access.end)?;
    if let PermissionChange::Some = change {
        dom.emit_shootdown(updates);
        updates.push(Update::PermissionUpdate { domain });
    };

    Ok(())
}

// ——————————————————————————— Interrupt Handler ———————————————————————————— //

/// Find the domain's manager who is responsible for handling the provided interrupt.
///
/// The domain itself is assumed to not be authorized to handle the domain.
/// Return none if no suitable manager exists.
pub(crate) fn find_interrupt_handler(
    domain: Handle<Domain>,
    interrupt: u64,
    domains: &DomainPool,
) -> Option<Handle<Domain>> {
    let mut handle = domain;
    while let Some(manager) = domains.get(handle) {
        if manager.interrupts & interrupt != 0 {
            return Some(handle);
        }
        let Some(next_handle) = manager.manager else {
            // This domain has no manager
            break;
        };
        handle = next_handle;
    }

    // Could not find a suitable manager
    None
}

// ——————————————————————————————— Enumerate ———————————————————————————————— //

pub(crate) fn next_capa(
    domain_handle: Handle<Domain>,
    token: NextCapaToken,
    regions: &RegionPool,
    domains: &mut DomainPool,
    contexts: &ContextPool,
) -> Option<(LocalCapa, NextCapaToken)> {
    let mut idx = token.idx;
    let len = domains[domain_handle].capas.len();
    while idx < len {
        let domain = &domains[domain_handle];
        if !domain.free_list.is_free(idx) {
            if domain.is_valid(idx, regions, domains, contexts) {
                // Found a valid capa
                let next_token = NextCapaToken { idx: idx + 1 };
                return Some((LocalCapa::new(idx), next_token));
            } else {
                // Capa has been invalidated
                let domain = &mut domains[domain_handle];
                domain.free_list.free(idx);
            }
        }
        idx += 1;
    }

    // No more capa
    None
}

// ——————————————————————————————— Revocation ——————————————————————————————— //

pub(crate) fn revoke(
    handle: DomainHandle,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
    updates: &mut UpdateBuffer,
    contexts: &mut ContextPool,
) -> Result<(), CapaError> {
    log::trace!("Revoke domain {}", handle);

    let domain = &mut domains[handle];
    if domain.is_being_revoked {
        // Already in the process of being revoked
        return Ok(());
    } else {
        // Mark as being revoked
        domain.is_being_revoked = true;
        updates.push(Update::RevokeDomain { domain: handle });
    }

    // Drop all capabilities
    let mut token = NextCapaToken::new();
    while let Some((capa, next_token)) = next_capa(handle, token, regions, domains, contexts) {
        token = next_token;
        revoke_capa(handle, capa, regions, domains, contexts, updates)?;
    }

    domains.free(handle);
    Ok(())
}

pub(crate) fn revoke_capa(
    handle: Handle<Domain>,
    local: LocalCapa,
    regions: &mut RegionPool,
    domains: &mut DomainPool,
    contexts: &mut ContextPool,
    updates: &mut UpdateBuffer,
) -> Result<(), CapaError> {
    let domain = &mut domains[handle];
    let capa = domain.get(local)?;

    match capa {
        // Those capa so not cause revocation side effects
        Capa::None => (),
        Capa::Channel(_) => (),
        Capa::Switch { to: _t, ctx: c } => {
            contexts.free(c);
        }

        // Those capa cause revocation side effects
        Capa::Region(region) => {
            region_capa::restore(region, regions, domains, updates)?;
        }
        Capa::Management(domain) => {
            revoke(domain, regions, domains, updates, contexts)?;
        }
    }

    // Deactivate capa
    let capa = domains[handle].get_mut(local).unwrap();
    //TODO(aghosn) this is why the capa is marked valid but none.
    *capa = Capa::None;

    Ok(())
}
