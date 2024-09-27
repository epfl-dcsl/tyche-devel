#![cfg_attr(not(test), no_std)]

mod capa;
pub mod context;
mod cores;
mod debug;
mod domain;
mod free_list;
mod gen_arena;
pub mod permission;
mod region;
mod remapper;
mod segment;
pub mod serializer;
mod update;
pub mod utils;

use core::ops::Index;

use attestation::hashing::HashEnclave;
use attestation::signature::EnclaveReport;
use capa::Capa;
pub use capa::{capa_type, CapaInfo};
use cores::{Core, CoreList};
use domain::{insert_capa, remove_capa, DomainHandle, DomainPool};
pub use domain::{Domain, LocalCapa, NextCapaToken};
pub use gen_arena::{GenArena, Handle};
pub use region::{
    AccessRights, MemOps, MemoryPermission, Region, RegionIterator, RegionTracker, MEMOPS_ALL,
    MEMOPS_EXTRAS,
};
use region::{PermissionIterator, TrackerPool, EMPTY_REGION};
pub use remapper::Remapper;
pub use segment::EffectiveRegionIterator;
use segment::{RegionCapa, RegionHash, RegionPool};
use update::UpdateBuffer;
pub use update::{Buffer, Update};

use crate::permission::{core_bits, trap_bits};
use crate::segment::EMPTY_REGION_CAPA;

/// Configuration for the static Capa Engine size.
pub mod config {
    pub const NB_DOMAINS: usize = 32;
    pub const NB_CAPAS_PER_DOMAIN: usize = 128;
    pub const NB_REGIONS: usize = 1024;
    pub const NB_TRACKER: usize = 1024;
    pub const NB_UPDATES: usize = 128;
    pub const NB_CORES: usize = 32; // NOTE: Can't be greater than 64 as we use 64 bits bitmaps.
    pub const NB_REMAP_REGIONS: usize = 128;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapaError {
    CannotDuplicate,
    InvalidDuplicate,
    InvalidInstall,
    InternalRegionError,
    InvalidRegion,
    InvalidCapa,
    WrongCapabilityType,
    CapabilityDoesNotExist,
    AlreadySealed,
    InsufficientPermissions,
    InvalidPermissions,
    OutOfMemory,
    CouldNotDeserializeInfo,
    InvalidCore,
    CouldNotHandleTrap,
    ValidTrapCausedExit,
    InvalidSwitch,
    InvalidVcpuType,
    InvalidOperation,
    InvalidValue,
    InvalidMemOps,
    AlreadyAliased,
    PlatformError,
}

pub struct CapaEngine {
    cores: CoreList,
    domains: DomainPool,
    regions: RegionPool,
    tracker: TrackerPool,
    updates: UpdateBuffer,
    id_counter: usize,
}

impl CapaEngine {
    pub const fn new() -> Self {
        const EMPTY_DOMAIN: Domain = Domain::new(0, false);
        const EMPTY_CORE: Core = Core::new();

        Self {
            cores: [EMPTY_CORE; config::NB_CORES],
            domains: GenArena::new([EMPTY_DOMAIN; config::NB_DOMAINS]),
            regions: GenArena::new([EMPTY_REGION_CAPA; config::NB_REGIONS]),
            tracker: GenArena::new([EMPTY_REGION; config::NB_TRACKER]),
            updates: UpdateBuffer::new(),
            id_counter: 0,
        }
    }

    pub fn create_manager_domain(&mut self, permissions: u64) -> Result<DomainHandle, CapaError> {
        log::trace!("Create new manager domain");

        let id = self.domain_id();
        match self.domains.allocate(Domain::new(id, false)) {
            Some(handle) => {
                domain::set_permission(
                    handle,
                    &mut self.domains,
                    permission::PermissionIndex::MonitorInterface,
                    permissions,
                )?;
                domain::set_permission(
                    handle,
                    &mut self.domains,
                    permission::PermissionIndex::AllowedCores,
                    core_bits::ALL,
                )?;
                domain::set_permission(
                    handle,
                    &mut self.domains,
                    permission::PermissionIndex::AllowedTraps,
                    trap_bits::ALL,
                )?;
                log::info!("About to seal");
                self.domains[handle].set_id(id)?;
                self.domains[handle].seal()?;
                self.updates
                    .push(Update::CreateDomain { domain: handle })
                    .unwrap();
                Ok(handle)
            }
            None => {
                log::info!("Failed to create new domain: out of memory");
                Err(CapaError::OutOfMemory)
            }
        }
    }

    pub fn start_domain_on_core(
        &mut self,
        domain: Handle<Domain>,
        core_id: usize,
    ) -> Result<(), CapaError> {
        log::trace!("Start CPU");

        if core_id > self.cores.len() {
            log::warn!(
                "Trid to initialize core {}, but there are only {} cores",
                core_id,
                self.cores.len()
            );
            return Err(CapaError::InvalidCore);
        }

        self.cores[core_id].initialize(domain)?;
        self.domains[domain].execute_on_core(core_id);

        Ok(())
    }

    pub fn create_domain(&mut self, manager: Handle<Domain>) -> Result<LocalCapa, CapaError> {
        self.domain_creation(manager, false)
    }

    pub fn create_io_domain(&mut self, manager: Handle<Domain>) -> Result<LocalCapa, CapaError> {
        self.domain_creation(manager, true)
    }

    pub fn revoke_domain(&mut self, domain: Handle<Domain>) -> Result<(), CapaError> {
        domain::revoke(
            domain,
            &mut self.regions,
            &mut self.domains,
            &mut self.tracker,
            &mut self.updates,
        )
    }

    pub fn create_root_region(
        &mut self,
        domain: DomainHandle,
        access: AccessRights,
    ) -> Result<LocalCapa, CapaError> {
        log::trace!("Create new root region");

        self.domains.get(domain).ok_or(CapaError::InvalidCapa)?;
        segment::create_root_region(
            domain,
            &mut self.regions,
            &mut self.domains,
            &mut self.tracker,
            &mut self.updates,
            access,
        )
    }

    pub fn alias_region(
        &mut self,
        domain: Handle<Domain>,
        region: LocalCapa,
        access: AccessRights,
    ) -> Result<LocalCapa, CapaError> {
        // Enforce permissions
        domain::has_permission(
            domain,
            &self.domains,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::CARVE,
        )?;

        let region = self.domains[domain].get(region)?.as_region()?;
        let handle = segment::alias(
            region,
            &mut self.regions,
            &mut self.domains,
            &mut self.tracker,
            &mut self.updates,
            access,
        )?;
        Ok(handle)
    }

    pub fn carve_region(
        &mut self,
        domain: Handle<Domain>,
        region: LocalCapa,
        access: AccessRights,
    ) -> Result<LocalCapa, CapaError> {
        // Enforce permissions
        domain::has_permission(
            domain,
            &self.domains,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::CARVE,
        )?;

        let region = self.domains[domain].get(region)?.as_region()?;
        let handle = segment::carve(
            region,
            &mut self.regions,
            &mut self.domains,
            &mut self.tracker,
            &mut self.updates,
            access,
        )?;
        Ok(handle)
    }

    pub fn create_revoke_capa(
        &mut self,
        domain: Handle<Domain>,
        region: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        let region = self.domains[domain].get(region)?.as_region()?;
        domain::has_capacity_for(domain, 1, &mut self.regions, &mut self.domains)?;
        let revoke_capa = Capa::RegionRevoke(region);
        insert_capa(domain, revoke_capa, &mut self.regions, &mut self.domains)
    }

    pub fn duplicate(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        // Enforce permissions
        domain::has_permission(
            domain,
            &self.domains,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::DUPLICATE,
        )?;
        domain::duplicate_capa(domain, capa, &mut self.regions, &mut self.domains)
    }

    pub fn send(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        self.send_with_flags(domain, capa, to, None, None)
    }

    pub fn send_with_flags(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
        flags: Option<MemOps>,
        hash: Option<RegionHash>,
    ) -> Result<LocalCapa, CapaError> {
        // Enforce permissions
        domain::has_permission(
            domain,
            &self.domains,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::SEND,
        )?;

        //TODO(all) as some code might fail below, we should not remove the capa
        // first.
        let to = self.domains[domain].get(to)?.as_channel()?;
        domain::has_capacity_for(to, 1, &mut self.regions, &mut self.domains)?;
        let capa = remove_capa(domain, capa, &mut self.domains)?;
        match capa {
            // No side effect for those capas
            Capa::None => (),
            Capa::Channel(_) => (),
            Capa::Switch { .. } => (),
            Capa::RegionRevoke(_) => (),

            Capa::Region(region) => {
                segment::send(
                    region,
                    &mut self.regions,
                    &mut self.domains,
                    &mut self.tracker,
                    &mut self.updates,
                    to,
                )?;

                // Set or unset the hash when sending the region
                if let Some(flags) = flags {
                    if !self.regions[region].add_hcv(flags) {
                        log::error!("Invalid hcvs! {:?}", flags);
                        return Err(CapaError::InvalidPermissions);
                    }
                    if flags.contains(MemOps::HASH) && hash.is_none() {
                        log::error!("Missing hash");
                        return Err(CapaError::InvalidValue);
                    }
                    match hash {
                        Some(hash) => self.regions[region].set_hash(&hash),
                        None => self.regions[region].reset_hash(),
                    }
                }
            }
            Capa::Management(domain) => {
                // TODO: check that no cycles are created
                domain::send_management(domain, &mut self.domains, to)?;
            }
        }

        // Move the capa to the new domain, can't fail as we checked for capacity already.
        insert_capa(to, capa, &mut self.regions, &mut self.domains)
    }

    // Mostly for debug.
    // TODO(Charly) how do I make this accessible to the tests but not the outside?
    pub fn get_effective_regions(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<EffectiveRegionIterator, CapaError> {
        let capa = self.domains[domain].get(capa)?;
        match capa {
            Capa::Region(region) => {
                return Ok(EffectiveRegionIterator::active_regions(
                    region,
                    &mut self.regions,
                ));
            }
            _ => {
                return Err(CapaError::InvalidCapa);
            }
        }
    }

    pub fn set_child_permission(
        &mut self,
        manager: Handle<Domain>,
        capa: LocalCapa,
        bitmap: permission::PermissionIndex,
        value: u64,
    ) -> Result<(), CapaError> {
        domain::has_permission(manager, &self.domains, bitmap, value)?;
        let domain = self.domains[manager].get(capa)?.as_management()?;
        domain::set_permission(domain, &mut self.domains, bitmap, value)?;
        Ok(())
    }

    pub fn get_child_permission(
        &mut self,
        manager: Handle<Domain>,
        capa: LocalCapa,
        bitmap: permission::PermissionIndex,
    ) -> Result<u64, CapaError> {
        let domain = self.domains[manager].get(capa)?.as_management()?;
        Ok(domain::get_permission(domain, &mut self.domains, bitmap))
    }

    // Should only be used for the root domain.
    pub fn set_domain_permission(
        &mut self,
        domain: Handle<Domain>,
        bitmap: permission::PermissionIndex,
        value: u64,
    ) -> Result<(), CapaError> {
        domain::set_permission(domain, &mut self.domains, bitmap, value)?;
        Ok(())
    }

    pub fn get_domain_permission(
        &mut self,
        domain: Handle<Domain>,
        perm: permission::PermissionIndex,
    ) -> u64 {
        domain::get_permission(domain, &self.domains, perm)
    }

    /// Seal a domain and return a switch handle for that domain.
    pub fn seal(
        &mut self,
        domain: Handle<Domain>,
        core: usize,
        capa: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        let capa = self.domains[domain].get(capa)?.as_management()?;
        self.domains[capa].seal()?;
        //TODO(aghosn)(Charly) we should create a switch capa for all cores?
        /*let mut cores = domain::get_permission(
            capa,
            &self.domains,
            permission::PermissionIndex::AllowedCores,
        );*/
        let trans = self.domains[domain]
            .find_capa(|x| match x {
                Capa::Switch { to, core: c } => {
                    if *to == capa && *c == core {
                        return true;
                    }
                    return false;
                }
                _ => return false,
            })
            .ok_or(CapaError::InvalidSwitch)?;
        //TODO: reenable once we clean up the kvm backend.
        /*let mut idx = 0;
        while cores != 0 && idx < 64 {
            if cores & 1 != 0 {
                let capa = self.domains[domain]
                    .find_capa(|x| match x {
                        Capa::Switch { to, core } => {
                            if *to == capa && *core == idx {
                                return true;
                            }
                            return false;
                        }
                        _ => return false,
                    })
                    .ok_or(CapaError::InvalidSwitch)?;
                if idx == core {
                    trans = Some(capa);
                }
            }
            cores = cores >> 1;
            idx += 1;
        }*/

        Ok(trans)
    }

    pub fn create_switch_on_core(
        &mut self,
        domain: Handle<Domain>,
        core: usize,
        capa: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        let capa = self.domains[domain].get(capa)?.as_management()?;
        let cores = domain::get_permission(
            capa,
            &self.domains,
            permission::PermissionIndex::AllowedCores,
        );
        if (1 << core) & cores == 0 {
            return Err(CapaError::InvalidCore);
        }
        let capa = insert_capa(
            domain,
            Capa::Switch { to: capa, core },
            &mut self.regions,
            &mut self.domains,
        )?;
        Ok(capa)
    }

    pub fn revoke(&mut self, domain: Handle<Domain>, capa: LocalCapa) -> Result<(), CapaError> {
        match self.domains[domain].get(capa)? {
            // Root regions can't be revoked.
            Capa::Region(region) if self.regions[region].is_root() => {
                Err(CapaError::InvalidOperation)
            }
            // If the domain is running, put an update rather than revoke.
            Capa::Management(dom) if self.domains[dom].cores() != 0 => {
                self.updates.push(Update::RevokeDomain {
                    manager: domain,
                    mgmt_capa: capa,
                    domain: dom,
                })
            }
            // All other are simply revoked
            _ => domain::revoke_capa(
                domain,
                capa,
                &mut self.regions,
                &mut self.domains,
                &mut self.tracker,
                &mut self.updates,
            ),
        }
    }

    /// Creates a new switch handle for the current domain.
    pub fn create_switch(
        &mut self,
        domain: Handle<Domain>,
        core: usize,
    ) -> Result<LocalCapa, CapaError> {
        domain::create_switch(domain, core, &mut self.regions, &mut self.domains)
    }

    /// Returns the new domain if the switch succeeds
    pub fn switch(
        &mut self,
        domain: Handle<Domain>,
        core: usize,
        delta: usize,
        capa: LocalCapa,
    ) -> Result<(), CapaError> {
        let mut quantum = delta;
        // Check the domain can be scheduled on the core.
        let (next_dom, _) = self.domains[domain].get(capa)?.as_switch()?;
        if (1 << core) & self.domains[next_dom].core_map() == 0 {
            log::error!("Attempt to schedule domain on unallowed core {}", core);
            log::error!("allowed: {:b}", self.domains[next_dom].core_map());
            log::error!("request: {:b}", 1 << core);
            return Err(CapaError::InvalidCore);
        }
        let return_capa = insert_capa(
            next_dom,
            Capa::Switch { to: domain, core },
            &mut self.regions,
            &mut self.domains,
        )?;
        remove_capa(domain, capa, &mut self.domains).unwrap(); // We already checked the capa
        self.domains[next_dom].execute_on_core(core);
        self.domains[domain].remove_from_core(core);
        self.cores[core].set_domain(next_dom);

        // Only allow delta quantums from manager to child.
        if let Some(m) = self.domains[domain].get_manager() {
            if m == next_dom {
                quantum = 0;
            }
        }

        self.updates
            .push(Update::Switch {
                domain: next_dom,
                return_capa,
                core,
                delta: quantum,
            })
            .unwrap();
        Ok(())
    }

    pub fn partial_switch(
        &mut self,
        domain: Handle<Domain>,
        manager: Handle<Domain>,
        core: usize,
    ) -> Result<(), CapaError> {
        self.domains[domain].remove_from_core(core);
        self.domains[manager].execute_on_core(core);
        self.cores[core].set_domain(manager);
        Ok(())
    }

    pub fn handle_trap(
        &mut self,
        domain: Handle<Domain>,
        core: usize,
        trap: u64,
        info: u64,
    ) -> Result<(), CapaError> {
        if self.domains[domain].can_handle(trap) {
            log::error!("The domain is able to handle its own trap, why did we exit?");
            return Err(CapaError::ValidTrapCausedExit);
        }
        //TODO: fix transition capa. This entire path is unstable and should be removed.
        let manager = domain::find_trap_handler(domain, trap, &self.domains)
            .ok_or(CapaError::CouldNotHandleTrap)?;
        self.updates
            .push(Update::Trap {
                manager,
                trap,
                info,
                core,
            })
            .unwrap();
        Ok(())
    }

    pub fn get_manager(&mut self, domain: Handle<Domain>) -> Result<Handle<Domain>, CapaError> {
        let dom = &self.domains[domain];
        dom.get_manager().ok_or(CapaError::CapabilityDoesNotExist)
    }

    pub fn handle_violation(
        &mut self,
        domain: Handle<Domain>,
        core_id: usize,
    ) -> Result<(), CapaError> {
        // Find the capability to simulate a switch.
        let dom = &self.domains[domain];
        let manager = dom.get_manager().ok_or(CapaError::CouldNotHandleTrap)?;
        let capa = dom
            .find_capa(|x| match x {
                Capa::Switch { to, core } => {
                    if *to == manager && *core == core_id {
                        return true;
                    }
                    return false;
                }
                _ => return false,
            })
            .ok_or(CapaError::InvalidCore)?;

        // No quantum delta when handling a violation.
        self.switch(domain, core_id, 0, capa)
    }

    pub fn enumerate(
        &mut self,
        domain: Handle<Domain>,
        token: NextCapaToken,
    ) -> Option<(CapaInfo, NextCapaToken, usize)> {
        let (index, next_token) =
            domain::next_capa(domain, token, &self.regions, &mut self.domains)?;

        let capa = self.domains[domain].get(index).unwrap();
        let info = capa.info(&self.regions, &self.domains)?;
        Some((info, next_token, index.as_usize()))
    }

    /// Enumerate all existing domains.
    ///
    /// NOTE: This function is intended for debug only, and is not (yet) implemented efficiently.
    pub fn enumerate_domains(
        &self,
        token: NextCapaToken,
    ) -> Option<(Handle<Domain>, NextCapaToken)> {
        let domain = self.domains.into_iter().skip(token.as_usize()).next()?;
        let next = NextCapaToken::from_usize(token.as_usize() + 1);
        Some((domain, next))
    }

    /// Returns the capacity of internal memory arena.
    ///
    /// In order, returns:
    /// - The domain pool capacity
    /// - The region pool capacity
    /// - The tracker pool capacity
    /// - Update buffer capacity
    /// This functions is mostly intended for debugging memory leaks in the capa engine.
    pub fn get_capacity(&self) -> (usize, usize, usize, usize) {
        (
            self.domains.capacity(),
            self.regions.capacity(),
            self.tracker.capacity(),
            self.updates.capacity(),
        )
    }

    pub fn get_domain_capa(
        &self,
        domain: Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<Handle<Domain>, CapaError> {
        self.domains[domain].get(capa)?.as_domain()
    }

    pub fn get_region_capa(
        &self,
        domain: Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<Option<&RegionCapa>, CapaError> {
        Ok(self
            .regions
            .get(self.domains[domain].get(capa)?.as_region()?))
    }

    pub fn get_domain_regions<'a>(
        &'a self,
        domain: Handle<Domain>,
    ) -> Result<RegionIterator<'a>, CapaError> {
        let Some(domain) = self.domains.get(domain) else {
            return Err(CapaError::InvalidValue);
        };
        Ok(domain.regions().iter(&self.tracker))
    }

    pub fn get_domain_permissions<'a>(
        &'a self,
        domain: Handle<Domain>,
    ) -> Result<PermissionIterator<'a>, CapaError> {
        let Some(domain) = self.domains.get(domain) else {
            return Err(CapaError::InvalidValue);
        };
        Ok(domain.regions().permissions(&self.tracker))
    }

    pub fn get_domain_cores(&self, domain: Handle<Domain>) -> Result<u64, CapaError> {
        Ok(self.domains[domain].cores())
    }

    pub fn pop_update(&mut self) -> Option<Update> {
        self.updates.pop()
    }

    pub fn set_hash(&mut self, domain: Handle<Domain>, hash: HashEnclave) {
        self.domains[domain].set_hash(hash);
    }

    pub fn set_report(&mut self, domain: Handle<Domain>, rep: EnclaveReport) {
        self.domains[domain].set_report(rep);
    }

    /// Writes the attestation into the provided buffer.
    ///
    /// Returns the number of bytes written. Raises an out of memory error if buffer space is
    /// insufficient.
    pub fn serialize_attestation(&self, buff: &mut [u8]) -> Result<usize, CapaError> {
        serializer::serialize(buff, &self.domains, &self.regions)
    }

    /// creates a new domain
    fn domain_creation(
        &mut self,
        manager: Handle<Domain>,
        io: bool,
    ) -> Result<LocalCapa, CapaError> {
        log::trace!("Create new domain");

        // Enforce permissions
        domain::has_permission(
            manager,
            &self.domains,
            permission::PermissionIndex::MonitorInterface,
            permission::monitor_inter_perm::SPAWN,
        )?;

        let id = self.domain_id();
        match self.domains.allocate(Domain::new(id, io)) {
            Some(handle) => {
                self.domains[handle].set_id(id)?;
                self.domains[handle].set_manager(manager);
                let capa = insert_capa(
                    manager,
                    Capa::management(handle),
                    &mut self.regions,
                    &mut self.domains,
                )?;
                // Create a Channel to the parent.
                let _chan = insert_capa(
                    handle,
                    Capa::Channel(manager),
                    &mut self.regions,
                    &mut self.domains,
                )?;
                self.updates
                    .push(Update::CreateDomain { domain: handle })
                    .unwrap();
                Ok(capa)
            }
            None => {
                log::info!("Failed to create new domain: out of memory");
                Err(CapaError::OutOfMemory)
            }
        }
    }

    /// Returns a fresh domain ID.
    fn domain_id(&mut self) -> usize {
        self.id_counter += 1;
        self.id_counter
    }

    /// Adds a permission update for the domain only if there isn't another one.
    pub fn conditional_permission_update(&mut self, target: Handle<Domain>) {
        let filter = |up: Update| match up {
            Update::PermissionUpdate {
                domain,
                core_map: _,
            } if domain == target => {
                return true;
            }
            _ => false,
        };
        if self.updates.contains(filter) {
            return;
        }
        let cores = self.domains[target].cores();
        self.updates
            .push(Update::PermissionUpdate {
                domain: target,
                core_map: cores,
            })
            .unwrap();
    }

    pub fn is_domain_sealed(&self, domain: Handle<Domain>) -> bool {
        self.domains[domain].is_sealed()
    }
}

impl Default for CapaEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ———————————————————————————————— Indexing ———————————————————————————————— //

impl Index<Handle<Domain>> for CapaEngine {
    type Output = Domain;

    fn index(&self, index: Handle<Domain>) -> &Self::Output {
        &self.domains[index]
    }
}
