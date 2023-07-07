#![cfg_attr(not(test), no_std)]

mod capa;
mod cores;
mod domain;
mod free_list;
mod gen_arena;
mod region;
mod region_capa;
mod update;
mod utils;

use core::ops::Index;

use capa::Capa;
pub use capa::{capa_type, CapaInfo};
use cores::{Core, CoreList};
use domain::{insert_capa, remove_capa, DomainHandle, DomainPool};
pub use domain::{permission, Domain, LocalCapa, NextCapaToken};
use gen_arena::GenArena;
pub use gen_arena::Handle;
pub use region::{AccessRights, RegionTracker};
use region_capa::{RegionCapa, RegionPool};
use update::UpdateBuffer;
pub use update::{Buffer, Update};

use crate::domain::{ALLOW_ALL_CORES, ALLOW_ALL_TRAPS};

/// Configuration for the static Capa Engine size.
pub mod config {
    pub const NB_DOMAINS: usize = 32;
    pub const NB_CAPAS_PER_DOMAIN: usize = 128;
    pub const NB_REGIONS_PER_DOMAIN: usize = 64;
    pub const NB_REGIONS: usize = 256;
    pub const NB_UPDATES: usize = 128;
    pub const NB_CORES: usize = 64; // NOTE: Can't be greater than 64 as we use 64 bits bitmaps.
}

#[derive(Clone, Copy, Debug)]
pub enum CapaError {
    CannotDuplicate,
    InvalidDuplicate,
    InvalidInstall,
    InternalRegionError,
    InvalidRegion,
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
}

pub struct CapaEngine {
    cores: CoreList,
    domains: DomainPool,
    regions: RegionPool,
    updates: UpdateBuffer,
    id_counter: usize,
}

impl CapaEngine {
    pub const fn new() -> Self {
        const EMPTY_DOMAIN: Domain = Domain::new(0);
        const EMPTY_CAPA: RegionCapa = RegionCapa::new_invalid();
        const EMPTY_CORE: Core = Core::new();

        Self {
            cores: [EMPTY_CORE; config::NB_CORES],
            domains: GenArena::new([EMPTY_DOMAIN; config::NB_DOMAINS]),
            regions: GenArena::new([EMPTY_CAPA; config::NB_REGIONS]),
            updates: UpdateBuffer::new(),
            id_counter: 0,
        }
    }

    pub fn create_manager_domain(&mut self, permissions: u64) -> Result<DomainHandle, CapaError> {
        log::trace!("Create new manager domain");

        let id = self.domain_id();
        match self.domains.allocate(Domain::new(id)) {
            Some(handle) => {
                domain::set_permissions(handle, &mut self.domains, permissions)?;
                domain::set_core_map(handle, &mut self.domains, ALLOW_ALL_CORES)?;
                domain::set_traps(handle, &mut self.domains, ALLOW_ALL_TRAPS)?;
                self.domains[handle].seal()?;
                self.updates.push(Update::CreateDomain { domain: handle });
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
        log::trace!("Create new domain");

        // Enforce permissions
        domain::has_permission(manager, &self.domains, permission::SPAWN)?;

        let id = self.domain_id();
        match self.domains.allocate(Domain::new(id)) {
            Some(handle) => {
                self.domains[handle].set_manager(manager);
                let capa = insert_capa(
                    manager,
                    Capa::management(handle),
                    &mut self.regions,
                    &mut self.domains,
                )?;
                self.updates.push(Update::CreateDomain { domain: handle });
                Ok(capa)
            }
            None => {
                log::info!("Failed to create new domain: out of memory");
                Err(CapaError::OutOfMemory)
            }
        }
    }

    pub fn revoke_domain(&mut self, domain: Handle<Domain>) -> Result<(), CapaError> {
        domain::revoke(
            domain,
            &mut self.regions,
            &mut self.domains,
            &mut self.updates,
        )
    }

    pub fn create_root_region(
        &mut self,
        domain: DomainHandle,
        access: AccessRights,
    ) -> Result<LocalCapa, CapaError> {
        log::trace!("Create new root region");

        match self
            .regions
            .allocate(RegionCapa::new(domain, access).confidential())
        {
            Some(handle) => {
                let capa = region_capa::install(
                    handle,
                    domain,
                    &mut self.regions,
                    &mut self.domains,
                    &mut self.updates,
                )?;
                Ok(capa)
            }
            None => {
                log::info!("Failed to create new domain: out of memory");
                Err(CapaError::OutOfMemory)
            }
        }
    }

    pub fn restore_region(
        &mut self,
        domain: Handle<Domain>,
        region: LocalCapa,
    ) -> Result<(), CapaError> {
        let region = self.domains[domain].get(region)?.as_region()?;
        region_capa::restore(
            region,
            &mut self.regions,
            &mut self.domains,
            &mut self.updates,
        )
    }

    pub fn segment_region(
        &mut self,
        domain: Handle<Domain>,
        region: LocalCapa,
        access_left: AccessRights,
        access_right: AccessRights,
    ) -> Result<(LocalCapa, LocalCapa), CapaError> {
        // Enforce permissions
        domain::has_permission(domain, &self.domains, permission::DUPLICATE)?;

        let region = self.domains[domain].get(region)?.as_region()?;
        let handles = region_capa::duplicate(
            region,
            &mut self.regions,
            &mut self.domains,
            &mut self.updates,
            access_left,
            access_right,
        )?;
        Ok(handles)
    }

    pub fn duplicate(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        // Enforce permissions
        domain::has_permission(domain, &self.domains, permission::DUPLICATE)?;
        domain::duplicate_capa(domain, capa, &mut self.regions, &mut self.domains)
    }

    pub fn send(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
    ) -> Result<(), CapaError> {
        // Enforce permissions
        domain::has_permission(domain, &self.domains, permission::SEND)?;

        //TODO(all) as some code might fail below, we should not remove the capa
        // first.
        let to = self.domains[domain].get(to)?.as_channel()?;
        let capa = remove_capa(domain, capa, &mut self.domains)?;
        match capa {
            // No side effect for those capas
            Capa::None => (),
            Capa::Channel(_) => (),
            Capa::Switch { .. } => (),

            // Sending those capa causes side effects
            Capa::Region(region) => {
                region_capa::send(
                    region,
                    &mut self.regions,
                    &mut self.domains,
                    &mut self.updates,
                    to,
                )?;
            }
            Capa::Management(domain) => {
                // TODO: check that no cycles are created
                domain::send_management(domain, &mut self.domains, to)?;
            }
        }

        // Move the capa to the new domain
        let Ok(_) = insert_capa(to, capa, &mut self.regions, &mut self.domains) else {
            log::info!("Send failed, receiving domain is out of memory");
            // Insert capa back, this should never fail as removed it just before
            insert_capa(domain, capa, &mut self.regions, &mut self.domains).unwrap();
            return Err(CapaError::OutOfMemory);
        };

        Ok(())
    }

    pub fn set_permissions(
        &mut self,
        manager: Handle<Domain>,
        capa: LocalCapa,
        permissions: u64,
    ) -> Result<(), CapaError> {
        let domain = self.domains[manager].get(capa)?.as_management()?;
        domain::set_permissions(domain, &mut self.domains, permissions)
    }

    pub fn set_domain_cores(
        &mut self,
        manager: Handle<Domain>,
        capa: LocalCapa,
        core_map: usize,
    ) -> Result<(), CapaError> {
        if (!self.domains[manager].core_map()) & (core_map as u64) != 0 {
            log::debug!("Attempted to increase core_map rights");
            log::debug!("allowed: {:b}", self.domains[manager].core_map());
            log::debug!("request: {:b}", core_map);
            return Err(CapaError::InsufficientPermissions);
        }
        let domain = self.domains[manager].get(capa)?.as_management()?;
        domain::set_core_map(domain, &mut self.domains, core_map as u64)
    }

    pub fn set_domain_traps(
        &mut self,
        manager: Handle<Domain>,
        capa: LocalCapa,
        traps: usize,
    ) -> Result<(), CapaError> {
        // Check that we are not granting more rights than what the manager has:
        if (!self.domains[manager].traps()) & (traps as u64) != 0 {
            log::debug!("Attempted to increase trap rights {:b}", traps);
            return Err(CapaError::InsufficientPermissions);
        }
        let domain = self.domains[manager].get(capa)?.as_management()?;
        domain::set_traps(domain, &mut self.domains, traps as u64)
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
            // Region are nor revoked, but restored.
            Capa::Region(region) => region_capa::restore(
                region,
                &mut self.regions,
                &mut self.domains,
                &mut self.updates,
            ),
            // All other are simply revoked
            _ => domain::revoke_capa(
                domain,
                capa,
                &mut self.regions,
                &mut self.domains,
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
        capa: LocalCapa,
    ) -> Result<(), CapaError> {
        // Check the domain can be scheduled on the core.
        if (1 << core) & self.domains[domain].core_map() == 0 {
            log::debug!("Attempt to schedule domain on unallowed core {}", core);
            log::debug!("allowed: {:b}", self.domains[domain].core_map());
            log::debug!("request: {:b}", 1 << core);
            return Err(CapaError::InvalidCore);
        }
        let (next_dom, _) = self.domains[domain].get(capa)?.as_switch()?;
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

        self.updates.push(Update::Switch {
            domain: next_dom,
            return_capa,
            core,
        });
        self.updates.push(Update::UpdateTraps {
            trap: self.domains[next_dom].traps(),
            core,
        });

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
        let manager = domain::find_trap_handler(domain, trap, &self.domains)
            .ok_or(CapaError::CouldNotHandleTrap)?;
        self.updates.push(Update::Trap {
            manager,
            trap,
            info,
            core,
        });
        // Also update the bitmap.
        self.updates.push(Update::UpdateTraps {
            trap: self.domains[manager].traps(),
            core,
        });

        Ok(())
    }

    pub fn enumerate(
        &mut self,
        domain: Handle<Domain>,
        token: NextCapaToken,
    ) -> Option<(CapaInfo, NextCapaToken)> {
        let (index, next_token) =
            domain::next_capa(domain, token, &self.regions, &mut self.domains)?;
        let capa = self.domains[domain].get(index).unwrap();
        let info = capa.info(&self.regions, &self.domains)?;
        Some((info, next_token))
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

    pub fn get_domain_capa(
        &self,
        domain: Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<Handle<Domain>, CapaError> {
        self.domains[domain].get(capa)?.as_domain()
    }

    pub fn pop_update(&mut self) -> Option<Update> {
        self.updates.pop()
    }

    /// Returns a fresh domain ID.
    fn domain_id(&mut self) -> usize {
        self.id_counter += 1;
        self.id_counter
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

impl Index<Handle<RegionCapa>> for CapaEngine {
    type Output = RegionCapa;

    fn index(&self, index: Handle<RegionCapa>) -> &Self::Output {
        &self.regions[index]
    }
}
