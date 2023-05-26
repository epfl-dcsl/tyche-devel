#![cfg_attr(not(test), no_std)]

mod capa;
mod context;
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
pub use context::Context;
use context::ContextPool;
use cores::{Core, CoreList};
use domain::{insert_capa, remove_capa, DomainHandle, DomainPool};
pub use domain::{permission, Domain, LocalCapa, NextCapaToken};
use gen_arena::GenArena;
pub use gen_arena::Handle;
pub use region::{AccessRights, RegionTracker};
use region_capa::{RegionCapa, RegionPool};
use update::UpdateBuffer;
pub use update::{Buffer, Update};

/// Configuration for the static Capa Engine size.
pub mod config {
    pub const NB_DOMAINS: usize = 32;
    pub const NB_CAPAS_PER_DOMAIN: usize = 128;
    pub const NB_REGIONS_PER_DOMAIN: usize = 64;
    pub const NB_REGIONS: usize = 256;
    pub const NB_UPDATES: usize = 128;
    pub const NB_CONTEXTS: usize = 128;
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
}

pub struct CapaEngine {
    cores: CoreList,
    domains: DomainPool,
    regions: RegionPool,
    updates: UpdateBuffer,
    contexts: ContextPool,
    id_counter: usize,
}

impl CapaEngine {
    pub const fn new() -> Self {
        const EMPTY_DOMAIN: Domain = Domain::new(0);
        const EMPTY_CAPA: RegionCapa = RegionCapa::new_invalid();
        const EMPTY_CONTEXT: Context = Context::new();
        const EMPTY_CORE: Core = Core::new();

        Self {
            cores: [EMPTY_CORE; config::NB_CORES],
            domains: GenArena::new([EMPTY_DOMAIN; config::NB_DOMAINS]),
            regions: GenArena::new([EMPTY_CAPA; config::NB_REGIONS]),
            updates: UpdateBuffer::new(),
            contexts: GenArena::new([EMPTY_CONTEXT; config::NB_UPDATES]),
            id_counter: 0,
        }
    }

    pub fn create_manager_domain(&mut self, permissions: u64) -> Result<DomainHandle, CapaError> {
        log::trace!("Create new manager domain");

        let id = self.domain_id();
        match self.domains.allocate(Domain::new(id)) {
            Some(handle) => {
                domain::set_permissions(handle, &mut self.domains, permissions)?;
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
    ) -> Result<Handle<Context>, CapaError> {
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

        self.contexts.allocate(Context::new()).ok_or({
            log::trace!("Unable to allocate context!");
            CapaError::OutOfMemory
        })
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
                    &mut self.contexts,
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
            &mut self.contexts,
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
                    &mut self.contexts,
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
            &mut self.contexts,
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
        domain::duplicate_capa(
            domain,
            capa,
            &mut self.regions,
            &mut self.domains,
            &mut self.contexts,
        )
    }

    pub fn send(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
    ) -> Result<(), CapaError> {
        // Enforce permissions
        domain::has_permission(domain, &self.domains, permission::SEND)?;

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
        let Ok(_) = insert_capa(to, capa, &mut self.regions, &mut self.domains, &mut self.contexts) else {
            log::info!("Send failed, receiving domain is out of memory");
            // Insert capa back, this should never fail as removed it just before
            insert_capa(domain, capa, &mut self.regions, &mut self.domains, &mut self.contexts).unwrap();
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

    /// Seal a domain and return a switch handle for that domain.
    pub fn seal(
        &mut self,
        domain: Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<(LocalCapa, Handle<Context>), CapaError> {
        let capa = self.domains[domain].get(capa)?.as_management()?;
        let context = self.contexts.allocate(Context::new()).ok_or({
            log::trace!("Unable to allocate context for seal!");
            CapaError::OutOfMemory
        })?;
        self.domains[capa].seal()?;
        let capa = insert_capa(
            domain,
            Capa::Switch {
                to: capa,
                ctx: context,
            },
            &mut self.regions,
            &mut self.domains,
            &mut self.contexts,
        )?;
        Ok((capa, context))
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
                &mut self.contexts,
                &mut self.updates,
            ),
        }
    }

    /// Creates a new switch handle for the current domain.
    pub fn create_switch(&mut self, domain: Handle<Domain>) -> Result<LocalCapa, CapaError> {
        domain::create_switch(
            domain,
            &mut self.regions,
            &mut self.domains,
            &mut self.contexts,
        )
    }

    /// Returns the new domain if the switch succeeds
    pub fn switch(
        &mut self,
        domain: Handle<Domain>,
        ctx: Handle<Context>,
        capa: LocalCapa,
        core_id: usize,
    ) -> Result<(Handle<Domain>, Handle<Context>, LocalCapa), CapaError> {
        let (next_dom, next_ctx) = self.domains[domain].get(capa)?.as_switch()?;
        let return_capa = insert_capa(
            next_dom,
            Capa::Switch { to: domain, ctx },
            &mut self.regions,
            &mut self.domains,
            &mut self.contexts,
        )?;
        remove_capa(domain, capa, &mut self.domains).unwrap(); // We already checked the capa
        self.domains[next_dom].execute_on_core(core_id);
        self.domains[domain].remove_from_core(core_id);

        self.updates.push(Update::Switch {
            domain: next_dom,
            context: next_ctx,
            core: core_id,
        });

        Ok((next_dom, next_ctx, return_capa))
    }

    pub fn handle_interrupt(&mut self, domain: Handle<Domain>, _core_id: usize, interrupt: u64) {
        let _ = domain::find_interrupt_handler(domain, interrupt, &self.domains);
        // TODO: generate an appropriate context switch event.
    }

    pub fn enumerate(
        &mut self,
        domain: Handle<Domain>,
        token: NextCapaToken,
    ) -> Option<(CapaInfo, NextCapaToken)> {
        let (index, next_token) = domain::next_capa(
            domain,
            token,
            &self.regions,
            &mut self.domains,
            &self.contexts,
        )?;
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
