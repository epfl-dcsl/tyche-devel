use core::fmt;
use core::sync::atomic::AtomicUsize;

use attestation::hashing::hash_region;
use capa_engine::config::NB_CORES;
use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, Buffer, CapaEngine, CapaError, CapaInfo, Domain, Handle, LocalCapa,
    MemOps, NextCapaToken, MEMOPS_ALL, MEMOPS_EXTRAS,
};
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;

use crate::allocator::PAGE_SIZE;
use crate::arch::cpuid;
use crate::attestation_domain::calculate_attestation_hash;
use crate::{align_down, align_up, calls};

// ———————————————————————————————— Updates ————————————————————————————————— //
/// Per-core updates
#[derive(Debug, Clone, Copy)]
pub enum CoreUpdate {
    TlbShootdown {
        src_core: LogicalID,
    },
    Switch {
        domain: Handle<Domain>,
        return_capa: LocalCapa,
        delta: usize,
    },
    Trap {
        manager: Handle<Domain>,
        trap: u64,
        info: u64,
    },
    DomainRevocation {
        revok: Handle<Domain>,
        next: Handle<Domain>,
    },
}

// ————————————————————————— Statics & Backend Data ————————————————————————— //
pub static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
pub static IO_DOMAIN: Mutex<Option<LocalCapa>> = Mutex::new(None);
pub static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
pub static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];

// —————————————————————— Constants for initialization —————————————————————— //
const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new());

// ————————————————————————— Static core remapping —————————————————————————— //

pub const CORE_REMAP_DEFAULT: AtomicUsize = AtomicUsize::new(usize::MAX);
pub static CORES_REMAP: [AtomicUsize; NB_CORES] = [CORE_REMAP_DEFAULT; NB_CORES];

// —————————————————————————— Trying to generalize —————————————————————————— //

/// Logical identifiers for cores.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct LogicalID(pub usize);
/// Physical identifiers for cores.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub struct PhysicalID(pub usize);

impl LogicalID {
    pub fn as_usize(self) -> usize {
        self.0
    }
    pub fn physical(self) -> PhysicalID {
        for (i, v) in CORES_REMAP.iter().enumerate() {
            if Self(v.load(core::sync::atomic::Ordering::SeqCst)) == self {
                return PhysicalID(i);
            }
        }
        panic!("Unable to find the physical ID for {}", self);
    }
}

impl fmt::Display for LogicalID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0) // Format the inner `usize` value
    }
}

impl PhysicalID {
    pub fn as_usize(self) -> usize {
        self.0
    }
    pub fn as_u32(self) -> u32 {
        self.0 as u32
    }
}

impl fmt::Display for PhysicalID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0) // Format the inner `usize` value
    }
}

// ——————————————————————— Platform dependent traits ———————————————————————— //

pub trait PlatformState {
    type DomainData;
    type Context;
    fn logical_id() -> LogicalID {
        let lid = CORES_REMAP[cpuid().as_usize()].load(core::sync::atomic::Ordering::SeqCst);
        assert!(lid != usize::MAX);
        LogicalID(lid)
    }
    fn find_buff(
        engine: &MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        addr: usize,
        end: usize,
    ) -> Option<usize>;
    fn remap_core_bitmap(bitmap: u64) -> u64;
    fn remap_core(core: usize) -> usize;
    fn max_cpus() -> usize;
    fn create_context(
        &mut self,
        engine: MutexGuard<CapaEngine>,
        current: Handle<Domain>,
        domain: Handle<Domain>,
        core: LogicalID,
    ) -> Result<(), CapaError>;

    fn platform_init_io_mmu(&self, addr: usize);

    fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, Self::DomainData>;

    fn get_context(domain: Handle<Domain>, core: LogicalID) -> MutexGuard<'static, Self::Context>;

    fn update_permission(domain: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) -> bool;

    fn create_domain(domain: Handle<Domain>);

    fn revoke_domain(domain: Handle<Domain>);

    fn apply_core_update(
        &mut self,
        domain: &mut Handle<Domain>,
        core_id: LogicalID,
        update: &CoreUpdate,
    );

    //TODO: check whether this is correct with logical IDs.
    fn platform_shootdown(&mut self, domain: &Handle<Domain>, core: LogicalID, trigger: bool);

    fn set_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: LogicalID,
        idx: usize,
        value: usize,
    ) -> Result<(), CapaError>;

    fn get_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: LogicalID,
        idx: usize,
    ) -> Result<usize, CapaError>;

    fn get_core_gp(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: LogicalID,
        result: &mut [usize],
    ) -> Result<(), CapaError>;

    fn dump_in_gp(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &mut Handle<Domain>,
        core: LogicalID,
        src: &[usize],
    ) -> Result<(), CapaError>;

    fn extract_from_gp(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: LogicalID,
        res: &mut [(usize, usize); 6],
    ) -> Result<(), CapaError>;

    fn check_overlaps(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> bool;

    fn map_region(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> Result<(), CapaError>;

    fn unmap_region(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        size: usize,
    ) -> Result<(), CapaError>;

    /// This assumes that the engine is locked!
    fn prepare_notify(domain: &Handle<Domain>, core_count: usize);

    fn notify_cores(domain: &Handle<Domain>, core_id: LogicalID, core_map: usize);

    fn acknowledge_notify(domain: &Handle<Domain>);

    fn finish_notify(domain: &Handle<Domain>);

    fn context_interrupted(&mut self, domain: &Handle<Domain>, core: LogicalID);

    fn find_hpa(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        gpa: usize,
        size: usize,
    ) -> Result<(usize, usize), CapaError>;
}

pub trait Monitor<T: PlatformState + 'static> {
    /// This function attempts to avoid deadlocks.
    /// It forces updates to be consumed upon failed attempts.
    fn lock_engine(state: &mut T, dom: &mut Handle<Domain>) -> MutexGuard<'static, CapaEngine> {
        let mut locked = CAPA_ENGINE.try_lock();
        while locked.is_none() {
            //TODO: fix me
            Self::apply_core_updates(state, dom);
            locked = CAPA_ENGINE.try_lock();
        }
        locked.unwrap()
    }

    fn do_init(state: &mut T, manifest: &'static Manifest) -> Handle<Domain> {
        // No one else is running yet
        let mut engine = CAPA_ENGINE.lock();
        let domain = engine
            .create_manager_domain(permission::monitor_inter_perm::ALL)
            .unwrap();
        Self::apply_updates(state, &mut engine);

        // Construct the address space with devices.
        let mut start: usize = 0;

        for i in 0..manifest.nb_devices {
            let device = &manifest.devices[i];
            if device.start % PAGE_SIZE != 0 || device.size % PAGE_SIZE != 0 {
                // For the moment, let's filter the weird ones out.
                continue;
            }

            let aligned_start = align_down(device.start as usize, PAGE_SIZE as usize);
            let possible_end = usize::min(
                align_down(device.start as usize, PAGE_SIZE as usize),
                manifest.poffset as usize,
            );

            // There is a RAM memory gap and it is at least a page.
            if start < aligned_start
                && start < possible_end
                && (possible_end - start) >= PAGE_SIZE as usize
            {
                // Create a region.
                engine
                    .create_root_region(
                        domain,
                        AccessRights {
                            start,
                            end: possible_end,
                            ops: MEMOPS_ALL,
                        },
                    )
                    .unwrap();
            }
            // Add the device.
            engine
                .create_root_device(
                    domain,
                    AccessRights {
                        start: device.start as usize,
                        end: (device.start + device.size) as usize,
                        ops: MEMOPS_ALL.union(MemOps::UNCACHEABLE),
                    },
                )
                .unwrap();
            // Align up.
            start = align_up((device.start + device.size) as usize, PAGE_SIZE as usize);
        }
        // The last entry if physical memory space is greater than device space.
        if start < manifest.poffset as usize {
            engine
                .create_root_region(
                    domain,
                    AccessRights {
                        start,
                        end: manifest.poffset as usize,
                        ops: MEMOPS_ALL,
                    },
                )
                .unwrap();
        }
        //TODO: call the platform?
        Self::apply_updates(state, &mut engine);
        // Save the initial domain.
        let mut initial_domain = INITIAL_DOMAIN.lock();
        *initial_domain = Some(domain);

        // Create and save the I/O domain.
        let io_domain = engine.create_io_domain(domain).unwrap();
        let mut initial_io_domain = IO_DOMAIN.lock();
        *initial_io_domain = Some(io_domain);
        //TODO figure that out.
        if manifest.iommu != 0 {
            state.platform_init_io_mmu(manifest.iommu as usize);
        }

        // TODO: taken from part of init_vcpu.
        engine
            .start_domain_on_core(domain, T::logical_id().as_usize())
            .expect("Failed to start initial domain on core");
        domain
    }

    fn start_initial_domain(state: &mut T) -> Handle<Domain> {
        let mut dom = INITIAL_DOMAIN.lock().unwrap();
        let mut engine = Self::lock_engine(state, &mut dom);
        engine
            .start_domain_on_core(dom, T::logical_id().as_usize())
            .unwrap();
        dom
    }

    fn do_debug<F>(state: &mut T, current: &mut Handle<Domain>, callback: F)
    where
        F: Fn(Handle<Domain>, &mut CapaEngine),
    {
        let mut engine = Self::lock_engine(state, current);
        let mut next = NextCapaToken::new();
        while let Some((domain, next_next)) = engine.enumerate_domains(next) {
            next = next_next;

            log::info!("Domain {}", domain.idx());
            let mut next_capa = NextCapaToken::new();
            while let Some((info, next_next_capa, idx)) = engine.enumerate(domain, next_capa) {
                next_capa = next_next_capa;
                log::info!(" - {} @{}", info, idx);
            }
            log::info!("Tracker:");
            for r in engine.get_domain_regions(domain).expect("Invalid domain") {
                log::info!("{}", r.1);
            }
            callback(domain, &mut engine);
        }
    }

    fn do_create_domain(
        state: &mut T,
        current: &mut Handle<Domain>,
    ) -> Result<LocalCapa, CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let mgmt = engine.create_domain(*current)?;
        Self::apply_updates(state, &mut engine);
        Ok(mgmt)
    }

    fn do_set(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        bitmap: permission::PermissionIndex,
        value: u64,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        engine.set_child_permission(*current, domain, bitmap, value)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_get(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        bitmap: permission::PermissionIndex,
    ) -> Result<usize, CapaError> {
        let mut engine = Self::lock_engine(state, current);
        Ok(engine.get_child_permission(*current, domain, bitmap)? as usize)
    }

    fn do_get_self(
        state: &mut T,
        current: &mut Handle<Domain>,
        bitmap: permission::PermissionIndex,
    ) -> Result<usize, CapaError> {
        let mut engine = Self::lock_engine(state, current);
        Ok(engine.get_domain_permission(*current, bitmap) as usize)
    }

    fn do_set_core(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: LogicalID,
        idx: usize,
        value: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        // Check the core is valid.
        let cores = engine.get_child_permission(
            *current,
            domain,
            permission::PermissionIndex::AllowedCores,
        )?;
        if cores & (1 << core.as_usize()) == 0 {
            return Err(CapaError::InvalidCore);
        }
        let domain = engine.get_domain_capa(*current, domain)?;
        state.set_core(&mut engine, &domain, core, idx, value)
    }

    fn do_get_core(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: LogicalID,
        idx: usize,
    ) -> Result<usize, CapaError> {
        let mut engine = Self::lock_engine(state, current);
        // Check the core is valid.
        let cores = engine.get_child_permission(
            *current,
            domain,
            permission::PermissionIndex::AllowedCores,
        )?;
        if cores & (1 << core.as_usize()) == 0 {
            return Err(CapaError::InvalidCore);
        }
        let domain = engine.get_domain_capa(*current, domain)?;
        state.get_core(&mut engine, &domain, core, idx)
    }

    fn do_get_all_gp(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: LogicalID,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let core_map = engine.get_child_permission(
            *current,
            domain,
            permission::PermissionIndex::AllowedCores,
        )?;
        if core_map & (1 << core.as_usize()) == 0 {
            return Err(CapaError::InvalidCore);
        }
        let domain = engine.get_domain_capa(*current, domain)?;
        let result: &mut [usize] = &mut [0; 15];
        state.get_core_gp(&mut engine, &domain, core, result)?;
        state.dump_in_gp(&mut engine, current, T::logical_id(), &result)?;
        Ok(())
    }

    fn do_write_fields(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: LogicalID,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let core_map = engine.get_child_permission(
            *current,
            domain,
            permission::PermissionIndex::AllowedCores,
        )?;
        if core_map & (1 << core.as_usize()) == 0 {
            return Err(CapaError::InvalidCore);
        }
        let mut values: [(usize, usize); 6] = [(0, 0); 6];
        state.extract_from_gp(&mut engine, current, T::logical_id(), &mut values)?;
        let domain = engine.get_domain_capa(*current, domain)?;
        for e in values {
            // Signal to skip.
            if e.0 == !(0 as usize) {
                break;
            }
            state.set_core(&mut engine, &domain, core, e.0, e.1)?;
        }
        Ok(())
    }

    fn do_seal(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        let core = T::logical_id();
        let mut engine = Self::lock_engine(state, current);
        //TODO: fix that.
        let capa = engine.seal(*current, core.as_usize(), domain)?;
        if let Ok(domain_capa) = engine.get_domain_capa(*current, domain) {
            calculate_attestation_hash(&mut engine, domain_capa);
        }

        Self::apply_updates(state, &mut engine);
        Ok(capa)
    }

    fn do_segment_region(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        is_shared: bool,
        start: usize,
        end: usize,
        prot: usize,
    ) -> Result<(LocalCapa, LocalCapa), CapaError> {
        let prot = MemOps::from_usize(prot)?;
        if prot.intersects(MEMOPS_EXTRAS) {
            log::error!("Invalid prots for segment region {:?}", prot);
            return Err(CapaError::InvalidOperation);
        }
        let mut engine = Self::lock_engine(state, current);
        let access = AccessRights {
            start,
            end,
            ops: prot,
        };
        let to_send = if is_shared {
            engine.alias_region(*current, capa, access)?
        } else {
            engine.carve_region(*current, capa, access)?
        };
        let to_revoke = engine.create_revoke_capa(*current, to_send)?;
        Self::apply_updates(state, &mut engine);
        Ok((to_send, to_revoke))
    }

    fn do_send(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        // Send is not allowed for region capa.
        // Use do_send_region instead.
        match engine.get_region_capa(*current, capa) {
            Ok(Some(_)) => return Err(CapaError::InvalidCapa),
            _ => {}
        }
        engine.send(*current, capa, to)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_send_region(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
        alias: usize,
        is_repeat: bool,
        size: usize,
        extra_rights: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let flags = MemOps::from_usize(extra_rights)?;
        if !flags.is_empty() && !flags.is_only_hcv() {
            log::error!("Invalid send region flags received: {:?}", flags);
            return Err(CapaError::InvalidPermissions);
        }
        // Get the capa first.
        let region_info = engine
            .get_region_capa(*current, capa)?
            .ok_or(CapaError::InvalidCapa)?
            .get_access_rights();
        let repeat = if is_repeat {
            let region_size = region_info.end - region_info.start;
            if size == 0 || (size % region_size) != 0 {
                return Err(CapaError::InvalidValue);
            }
            size / region_size
        } else {
            // Not a repeat, spans the entire thing.
            1
        };
        // Check for an overlap first.
        {
            let target = engine.get_domain_capa(*current, to)?;
            if state.check_overlaps(&mut engine, target, alias, repeat, &region_info) {
                return Err(CapaError::AlreadyAliased);
            }
        }

        if !flags.is_empty() {
            // NOTE: we are missing some checks here, not all memory covered by regions can be accessed
            // in the current design.
            let hash = if flags.contains(MemOps::HASH) {
                let data = unsafe {
                    core::slice::from_raw_parts(
                        region_info.start as *const u8,
                        region_info.end - region_info.start,
                    )
                };
                let hash = hash_region(data);
                Some(hash)
            } else {
                None
            };
            let opt_flags = if flags.is_empty() { None } else { Some(flags) };
            let _ = engine.send_with_flags(*current, capa, to, opt_flags, hash);
        } else {
            let _ = engine.send(*current, capa, to)?;
        }
        {
            let target = engine.get_domain_capa(*current, to)?;
            state.map_region(&mut engine, target, alias, repeat, &region_info)?;
        }
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_enumerate(
        state: &mut T,
        current: &mut Handle<Domain>,
        token: NextCapaToken,
    ) -> Option<(CapaInfo, NextCapaToken, usize)> {
        let mut engine = Self::lock_engine(state, current);
        engine.enumerate(*current, token)
    }

    fn do_revoke(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        engine.revoke(*current, capa)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_revoke_region(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        to: LocalCapa,
        alias: usize,
        size: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        {
            let dom = engine.get_domain_capa(*current, to)?;
            let _ = state.unmap_region(&mut engine, dom, alias, size).unwrap();
        }
        engine.revoke(*current, capa)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_duplicate(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
    ) -> Result<LocalCapa, CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let new_capa = engine.duplicate(*current, capa)?;
        Self::apply_updates(state, &mut engine);
        Ok(new_capa)
    }

    fn do_switch(
        state: &mut T,
        current: &mut Handle<Domain>,
        capa: LocalCapa,
        core: LogicalID,
        delta: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        engine.switch(*current, core.as_usize(), delta, capa)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_return_to_manager(
        state: &mut T,
        current: &mut Handle<Domain>,
        core_id: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        engine.handle_violation(*current, core_id)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_serialize_attestation(
        state: &mut T,
        domain_handle: &mut Handle<Domain>,
        addr: usize,
        len: usize,
    ) -> Result<usize, CapaError> {
        let engine = Self::lock_engine(state, domain_handle);
        //TODO maybe we have some more arguments
        let buff = T::find_buff(&engine, *domain_handle, addr, addr + len);
        let Some(buff) = buff else {
            log::info!("Invalid buffer in serialize attestation");
            return Err(CapaError::InsufficientPermissions);
        };
        let buff = unsafe { core::slice::from_raw_parts_mut(buff as *mut u8, len) };
        engine.serialize_attestation(buff)
    }

    fn do_init_child_context(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: LogicalID,
    ) -> Result<LocalCapa, CapaError> {
        if core.as_usize() > T::max_cpus() {
            log::error!(
                "Attempt to set context on unallowed core {} max_cpus {}",
                core,
                T::max_cpus(),
            );
            return Err(CapaError::InvalidCore);
        }

        let mut engine = Self::lock_engine(state, current);
        let capa = engine.create_switch_on_core(*current, core.as_usize(), domain)?;
        let domain = engine.get_domain_capa(*current, domain)?;
        T::create_context(state, engine, *current, domain, core)?;
        return Ok(capa);
    }

    fn do_get_hpa(
        state: &mut T,
        current: &mut Handle<Domain>,
        start: usize,
        size: usize,
    ) -> Result<(usize, usize), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        state.find_hpa(&mut engine, *current, start, size)
    }

    fn do_monitor_call(
        state: &mut T,
        domain: &mut Handle<Domain>,
        call: usize,
        args: &[usize; 6],
        res: &mut [usize; 6],
    ) -> Result<bool, CapaError> {
        match call {
            calls::CREATE_DOMAIN => {
                let capa = Self::do_create_domain(state, domain)?;
                res[0] = capa.as_usize();
                return Ok(true);
            }
            calls::SEAL_DOMAIN => {
                log::trace!("Seal Domain on core {}", T::logical_id());
                let capa = Self::do_seal(state, domain, LocalCapa::new(args[0]))?;
                res[0] = capa.as_usize();
                return Ok(true);
            }
            calls::SEND => {
                log::trace!("Send on core {}", T::logical_id());
                Self::do_send(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LocalCapa::new(args[1]),
                )?;
                return Ok(true);
            }
            calls::SEND_REGION => {
                log::trace!("Send region on core {}", T::logical_id());
                Self::do_send_region(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LocalCapa::new(args[1]),
                    args[2],
                    args[3] != 0,
                    args[4],
                    args[5],
                )?;
                // The API expects the revocation handle in the first arg.
                res[0] = args[0];
                return Ok(true);
            }
            calls::SEGMENT_REGION => {
                log::trace!("Segment region on core {}", T::logical_id());
                let (to_send, to_revoke) = Self::do_segment_region(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    args[1] != 0,
                    args[2],
                    args[3],
                    args[4],
                )?;
                res[0] = to_send.as_usize();
                res[1] = to_revoke.as_usize();
                return Ok(true);
            }
            calls::REVOKE => {
                log::trace!("Revoke on core {}", T::logical_id());
                Self::do_revoke(state, domain, LocalCapa::new(args[0]))?;
                return Ok(true);
            }
            calls::DUPLICATE => {
                log::trace!("Duplicate");
                let capa = Self::do_duplicate(state, domain, LocalCapa::new(args[0]))?;
                res[0] = capa.as_usize();
                return Ok(true);
            }
            calls::ENUMERATE => {
                log::trace!("Enumerate on core {}", T::logical_id());
                if let Some((info, next, _idx)) =
                    Self::do_enumerate(state, domain, NextCapaToken::from_usize(args[0]))
                {
                    let (v1, v2, v3) = info.serialize();
                    res[0] = v1;
                    res[1] = v2;
                    res[2] = v3 as usize;
                    res[3] = next.as_usize();
                } else {
                    res[3] = 0;
                }
                return Ok(true);
            }
            calls::SWITCH => {
                log::trace!(
                    "Switch on core {} from {} with capa {} quantum {}",
                    T::logical_id(),
                    domain.idx(),
                    args[0],
                    args[1],
                );
                Self::do_switch(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    T::logical_id(),
                    args[1],
                )?;
                return Ok(false);
            }
            calls::RETURN_TO_MANAGER => {
                log::trace!("Return to manager from dom {}", domain.idx());
                Self::do_handle_violation(state, domain)?;
                //Self::do_return_to_manager(state, domain, cpuid())?;
                return Ok(false);
            }
            calls::CALL_MANAGER => {
                log::trace!("Calling manager from dom {}", domain.idx());
                // This is handled like a violation. with the exception that
                // we move the instruction pointer before.
                // TODO(aghosn): might end up doing the same for regular vms.
                Self::do_handle_violation(state, domain)?;
                return Ok(false);
            }
            calls::EXIT => {
                todo!("Exit called")
            }
            calls::DEBUG => {
                log::info!(
                    "Debug called with {:#x} from dom{} on core {}\n\n",
                    args[0],
                    domain.idx(),
                    T::logical_id()
                );
                return Ok(false);
            }
            calls::CONFIGURE => {
                log::trace!("Configure on core {}", T::logical_id());
                let result = if let Some(bitmap) = permission::PermissionIndex::from_usize(args[0])
                {
                    let mut value = args[2] as u64;
                    if bitmap == permission::PermissionIndex::AllowedCores {
                        value = T::remap_core_bitmap(value);
                    }
                    match Self::do_set(state, domain, LocalCapa::new(args[1]), bitmap, value) {
                        Ok(_) => 0,
                        Err(e) => {
                            log::error!("Configuration error: {:?}", e);
                            log::error!("Bitmap: {:?}, value {:#x}", bitmap, value);
                            1
                        }
                    }
                } else {
                    log::error!("Invalid configuration target");
                    1
                };
                res[0] = result;
                return Ok(true);
            }
            calls::CONFIGURE_CORE => {
                Self::do_set_core(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LogicalID(T::remap_core(args[1])),
                    args[2],
                    args[3],
                )?;
                return Ok(true);
            }
            calls::GET_CONFIG_CORE => {
                log::trace!("Get config core on core {}", T::logical_id());
                let value = Self::do_get_core(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LogicalID(T::remap_core(args[1])),
                    args[2],
                )?;
                res[0] = value;
                return Ok(true);
            }
            calls::ALLOC_CORE_CONTEXT => {
                let capa = Self::do_init_child_context(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LogicalID(T::remap_core(args[1])),
                )?;
                res[0] = capa.as_usize();
                return Ok(true);
            }
            calls::READ_ALL_GP => {
                log::trace!("Read all gp on core {}", T::logical_id());
                Self::do_get_all_gp(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LogicalID(T::remap_core(args[1])),
                )?;
                return Ok(false);
            }
            calls::WRITE_ALL_GP => {
                todo!("Implement!!!");
            }
            calls::WRITE_FIELDS => {
                log::trace!("Write fields on core {}", T::logical_id());
                Self::do_write_fields(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LogicalID(T::remap_core(args[1])),
                )?;
                return Ok(true);
            }
            calls::SELF_CONFIG => {
                todo!("Implement!!!");
            }
            calls::REVOKE_ALIASED_REGION => {
                log::trace!("Revoke aliased region on core {}", T::logical_id());
                Self::do_revoke_region(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LocalCapa::new(args[1]),
                    args[2],
                    args[3],
                )?;
                return Ok(true);
            }
            calls::SERIALIZE_ATTESTATION => {
                let written = Self::do_serialize_attestation(state, domain, args[0], args[1])?;
                res[0] = written;
                return Ok(true);
            }
            calls::GET_HPA => {
                let (start, size) = Self::do_get_hpa(state, domain, args[0], args[1])?;
                res[0] = start;
                res[1] = size;
                return Ok(true);
            }
            _ => {
                log::info!("The invalid operation: {}", call);
                return Err(CapaError::InvalidOperation);
            }
        }
    }

    fn do_handle_violation(state: &mut T, current: &mut Handle<Domain>) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let core = T::logical_id();
        state.context_interrupted(current, core);
        engine.handle_violation(*current, core.as_usize())?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn apply_updates(state: &mut T, engine: &mut MutexGuard<CapaEngine>) {
        while let Some(update) = engine.pop_update() {
            log::trace!("Update: {}", update);
            match update {
                capa_engine::Update::PermissionUpdate { domain, core_map } => {
                    let core_id = T::logical_id();
                    log::trace!(
                        "cpu {} processes PermissionUpdate with core_map={:b}",
                        core_id,
                        core_map
                    );
                    // Do we have to process updates
                    if T::update_permission(domain, engine) {
                        let mut core_count = core_map.count_ones() as usize;
                        if (1 << core_id.as_usize()) & core_map != 0 {
                            state.platform_shootdown(&domain, core_id, true);
                        } else {
                            // We will wait on the barrier.
                            core_count += 1;
                        }
                        // Prepare the update.
                        T::prepare_notify(&domain, core_count);
                        for core in BitmapIterator::new(core_map) {
                            if LogicalID(core) == core_id {
                                continue;
                            }
                            let mut core_updates = CORE_UPDATES[core as usize].lock();
                            core_updates
                                .push(CoreUpdate::TlbShootdown { src_core: core_id })
                                .unwrap();
                        }
                        T::notify_cores(&domain, core_id, core_map as usize);
                        T::acknowledge_notify(&domain);
                        T::finish_notify(&domain);
                    }
                }
                capa_engine::Update::Cleanup { start, end } => {
                    let size = end.checked_sub(start).unwrap();
                    log::trace!("Cleaning up region [{:#x}, {:#x}]", start, end);
                    // WARNING: for now we do not check that the region points to valid memory!
                    // In particular, the current root region contains more than valid ram, and also
                    // include devices.
                    unsafe {
                        let region = core::slice::from_raw_parts_mut(start as *mut u8, size);
                        region.fill(0);
                    }
                }
                capa_engine::Update::RevokeDomain {
                    manager,
                    mgmt_capa,
                    domain,
                } => {
                    let core_map = engine.get_domain_core_map(domain).unwrap();
                    let cores = engine.get_domain_cores(domain).unwrap();
                    let core_id = T::logical_id();

                    // All the possible cores need to block on the domain sync.
                    let mut all_cores_count = core_map.count_ones() as usize;
                    if (core_map & (1 << core_id.as_usize())) == 0 {
                        // Add the current core the list.
                        all_cores_count += 1;
                    } else {
                        // Make sure we flush on this core too.
                        T::revoke_domain(domain);
                    }

                    // The algorithm includes 2 barriers:
                    // 1) Send a message to all the cores on which the domain could run.
                    //  a) The engine is locked guaranteeing atomicity
                    // 2) All relevant cores get the update, those running the domain switch to the
                    //    manager. All of them flush the state if necessary.
                    // 3) They notify this thread that it's done on the domain's barrier.
                    // 3) Everyone blocks on the manager's barrier.
                    // 4) The main thread can safely update other
                    //    cores engine state.
                    // 5) The main thread notifies everyone to resume.
                    let manager_core_map = engine
                        .get_domain_permission(manager, permission::PermissionIndex::AllowedCores);
                    T::prepare_notify(&domain, all_cores_count);
                    T::prepare_notify(&manager, all_cores_count);
                    for core in BitmapIterator::new(core_map) {
                        if LogicalID(core) == core_id {
                            continue;
                        }
                        // If the core is part of the ones where the manager needs to be scheduled,
                        // check the manager can run on there.
                        if ((1 << core) & cores != 0) && (manager_core_map & (1 << core) == 0) {
                            panic!("The manager cannot run on the target core!");
                        }
                        let mut core_updates = CORE_UPDATES[core as usize].lock();
                        core_updates
                            .push(CoreUpdate::DomainRevocation {
                                revok: domain,
                                next: manager,
                            })
                            .unwrap();
                    }
                    T::notify_cores(&domain, core_id, core_map as usize);
                    T::acknowledge_notify(&domain);
                    // All cores running the revoked domain should have stopped
                    // and are blocking on the manager's signal.
                    for core in BitmapIterator::new(cores) {
                        // Change the domain on the core.
                        engine.partial_switch(domain, manager, core).unwrap();
                    }
                    // Check the domain's cores have been preempted.
                    assert_eq!(engine.get_domain_cores(domain), Ok(0));
                    engine.revoke_domain_capa(manager, mgmt_capa).unwrap();
                    // Free the threads
                    T::acknowledge_notify(&manager);
                }
                capa_engine::Update::CreateDomain { domain } => T::create_domain(domain),
                capa_engine::Update::Switch {
                    domain,
                    return_capa,
                    core,
                    delta,
                } => {
                    let mut core_updates = CORE_UPDATES[core as usize].lock();
                    core_updates
                        .push(CoreUpdate::Switch {
                            domain,
                            return_capa,
                            delta,
                        })
                        .unwrap();
                }
                capa_engine::Update::Trap {
                    manager,
                    trap,
                    info,
                    core,
                } => {
                    let mut core_updates = CORE_UPDATES[core as usize].lock();
                    core_updates
                        .push(CoreUpdate::Trap {
                            manager,
                            trap,
                            info,
                        })
                        .unwrap();
                }
            }
        }
    }

    fn apply_core_updates(state: &mut T, current: &mut Handle<Domain>) {
        let core = T::logical_id();
        let mut update_queue = CORE_UPDATES[core.as_usize()].lock();
        while let Some(update) = update_queue.pop() {
            state.apply_core_update(current, core, &update);
        }
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //
impl core::fmt::Display for CoreUpdate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CoreUpdate::TlbShootdown { src_core } => write!(f, "TLB Shootdown {}", src_core),
            CoreUpdate::Switch { domain, .. } => write!(f, "Switch({})", domain),
            CoreUpdate::Trap {
                manager,
                trap: interrupt,
                info: inf,
            } => {
                write!(f, "Trap({}, {} | {:b})", manager, interrupt, inf)
            }
            CoreUpdate::DomainRevocation { revok, next } => write!(
                f,
                "Domain Revocation {} goes to {}",
                revok.idx(),
                next.idx()
            ),
        }
    }
}
