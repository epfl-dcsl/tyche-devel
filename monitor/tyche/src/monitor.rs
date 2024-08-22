use core::{mem, panic, slice};

use attestation::hashing::hash_region;
use capa_engine::config::NB_CORES;
use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, Buffer, CapaEngine, CapaError, CapaInfo, Domain, Handle, LocalCapa,
    MemOps, NextCapaToken, RegionIterator, ResourceKind, MEMOPS_ALL, MEMOPS_EXTRAS,
};
use mmu::ioptmapper::PAGE_SIZE;
use mmu::memory_coloring::color_to_phys::MemoryRegionKind;
use mmu::memory_coloring::{ColorBitmap, MemoryRange, PartitionBitmap};
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
use vmx::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};

use crate::arch::cpuid;
use crate::arch::paravirt_iommu::{Command as PvIOMMUCommand, PvIommuResult};
use crate::attestation_domain::calculate_attestation_hash;
use crate::calls;
use crate::data_transfer::{
    DataPoolDirection, DataPoolEntry, DataTransferPool, DataTransferPoolHandle,
};

// ———————————————————————————————— Updates ————————————————————————————————— //
/// Per-core updates
#[derive(Debug, Clone, Copy)]
pub enum CoreUpdate {
    TlbShootdown {
        src_core: usize,
    },
    Switch {
        domain: Handle<Domain>,
        return_capa: LocalCapa,
    },
    Trap {
        manager: Handle<Domain>,
        trap: u64,
        info: u64,
    },
}

// ————————————————————————— Statics & Backend Data ————————————————————————— //
pub static CAPA_ENGINE: Mutex<CapaEngine> = Mutex::new(CapaEngine::new());
pub static IO_DOMAIN: Mutex<Option<LocalCapa>> = Mutex::new(None);
pub static INITIAL_DOMAIN: Mutex<Option<Handle<Domain>>> = Mutex::new(None);
pub static CORE_UPDATES: [Mutex<Buffer<CoreUpdate>>; NB_CORES] = [EMPTY_UPDATE_BUFFER; NB_CORES];

// —————————————————————— Constants for initialization —————————————————————— //
const EMPTY_UPDATE_BUFFER: Mutex<Buffer<CoreUpdate>> = Mutex::new(Buffer::new());

// —————————————————————————— Trying to generalize —————————————————————————— //

//trait for platform specific behaviour
pub trait PlatformState {
    type DomainData;
    type Context;
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
        core: usize,
    ) -> Result<(), CapaError>;

    fn create_new_domain_data_entry(
        &self,
        domain_handle: &mut Handle<Domain>,
        direction: DataPoolDirection,
    ) -> Result<DataTransferPoolHandle, CapaError>;

    fn store_domain_data(
        &self,
        domain_handle: &mut Handle<Domain>,
        data_handle: DataTransferPoolHandle,
        data: &[u8],
        mark_finished: bool,
    ) -> Result<(), CapaError>;

    fn consume_data_from_domain(
        &self,
        domain_handle: &mut Handle<Domain>,
        data_handle: DataTransferPoolHandle,
    ) -> Result<DataPoolEntry, CapaError>;

    fn copy_data_to_domain(
        &self,
        domain_handle: &mut Handle<Domain>,
        data_handle: DataTransferPoolHandle,
    ) -> Result<([u8; DataTransferPool::TO_DOMAIN_CHUNCK_SIZE], usize, usize), CapaError>;

    /// Wrapper to execute command in paravirtualized IOMMU driver in Tyche
    fn execute_pv_iommu_cmd(
        &self,
        cmd: PvIOMMUCommand,
        raw_buf: &[u8],
        domain_handle: &mut Handle<Domain>,
    ) -> Result<PvIommuResult, &'static str>;

    fn get_hpa(&self, domain_handle: Handle<Domain>, gpa: GuestPhysAddr) -> Option<HostPhysAddr>;

    fn platform_init_io_mmu(&self, addr: HostVirtAddr);

    fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, Self::DomainData>;

    fn get_context(domain: Handle<Domain>, core: usize) -> MutexGuard<'static, Self::Context>;

    fn update_permission(domain: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) -> bool;

    fn create_domain(domain: Handle<Domain>);

    fn revoke_domain(_domain: Handle<Domain>);

    fn apply_core_update(
        &mut self,
        domain: &mut Handle<Domain>,
        core_id: usize,
        update: &CoreUpdate,
    );

    fn platform_shootdown(&mut self, domain: &Handle<Domain>, core: usize, trigger: bool);

    fn set_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        idx: usize,
        value: usize,
    ) -> Result<(), CapaError>;

    fn get_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        idx: usize,
    ) -> Result<usize, CapaError>;

    fn get_core_gp(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
        result: &mut [usize],
    ) -> Result<(), CapaError>;

    fn dump_in_gp(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &mut Handle<Domain>,
        core: usize,
        src: &[usize],
    ) -> Result<(), CapaError>;

    fn extract_from_gp(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: usize,
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

    fn map_compactified_range(
        &mut self,
        domain: Handle<Domain>,
        color_range: (usize, usize),
        include_devices: bool,
        start_gpa: usize,
        regions_iter: RegionIterator,
    ) -> Result<(), CapaError>;

    fn map_region(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        size: usize,
        repeat: usize,
    ) -> Result<(), CapaError>;

    fn unmap_region(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        size: usize,
    ) -> Result<(), CapaError>;

    fn prepare_notify(domain: &Handle<Domain>, core_count: usize);

    fn notify_cores(domain: &Handle<Domain>, core_id: usize, core_map: usize);

    fn acknowledge_notify(domain: &Handle<Domain>);

    fn finish_notify(domain: &Handle<Domain>);

    fn context_interrupted(&mut self, domain: &Handle<Domain>, core: usize);
}

pub trait Monitor<T: PlatformState + 'static> {
    /// This function attempts to avoid deadlocks.
    /// It forces updates to be consumed upon failed attempts.
    fn lock_engine(state: &mut T, dom: &mut Handle<Domain>) -> MutexGuard<'static, CapaEngine> {
        let mut locked = CAPA_ENGINE.try_lock();
        while locked.is_none() {
            //TODO: fix me
            Self::apply_core_updates(state, dom, cpuid());
            locked = CAPA_ENGINE.try_lock();
        }
        locked.unwrap()
    }

    /*
    1) create one root region for each physical contiguous range of memory that should initially be available to dom0
    2) create one root region for each device memory
    3) delay creation of remaining memory, as creating a root region will also always give dom0 access to it (regions are sth. that is allowed by capabilities and cannot really exist on their own to my understanding)
     */
    fn do_init(state: &mut T, manifest: &'static Manifest) -> Handle<Domain> {
        log::info!("do_init");
        if manifest.iommu_hva != 0 {
            log::info!(
                "Initializing IOMMU in tyche using HVA 0x{:013x}",
                manifest.iommu_hva
            );
            state.platform_init_io_mmu(HostVirtAddr::new(manifest.iommu_hva as usize));
        }

        // No one else is running yet
        let mut engine = CAPA_ENGINE.lock();
        let domain = engine
            .create_manager_domain(permission::monitor_inter_perm::ALL)
            .unwrap();
        Self::apply_updates(state, &mut engine);
        //colors that should be used by Linux in dom0
        let mut dom0_partititons = PartitionBitmap::new();
        //parse manifset to configure colors that should be used by Linux in dom0
        match manifest.dom0_memory {
            MemoryRange::ColoredRange(cr) => {
                log::info!(
                    "Using colors [{},{}[ for dom0",
                    cr.first_color,
                    cr.first_color + cr.color_count
                );
                for v in cr.first_color..(cr.first_color + cr.color_count) {
                    dom0_partititons.set(v as usize, true);
                }
            }
            MemoryRange::SinglePhysContigRange(_) => {
                panic!("SinglePhysContigRange is not supported")
            }
            // In this case we don't want any specific colors for dom0
            MemoryRange::AllRamRegionInRange(_) => {
                dom0_partititons.set_all(true);
            }
        }
        //create CAPAs for dom0
        //TODO: we can again create root regions for all memory. The remapper will take care of differentiating between core memory and additional memory
        for mr in manifest.get_boot_mem_regions() {
            match mr.kind {
                MemoryRegionKind::UseableRAM => match manifest.dom0_memory {
                    MemoryRange::ColoredRange(_) => {
                        engine
                            .create_root_region(
                                domain,
                                AccessRights {
                                    start: mr.start as usize,
                                    end: mr.end as usize,
                                    resource: ResourceKind::ram_with_all_partitions(),
                                    ops: MEMOPS_ALL,
                                },
                            )
                            .unwrap();
                    }
                    MemoryRange::AllRamRegionInRange(pr) => {
                        //For phys contig case, only create capa for ram if it is inside the
                        //allowed range
                        if mr.start >= pr.range.start.as_u64() && mr.end <= pr.range.end.as_u64() {
                            engine
                                .create_root_region(
                                    domain,
                                    AccessRights {
                                        start: mr.start as usize,
                                        end: mr.end as usize,
                                        resource: ResourceKind::ram_with_all_partitions(),
                                        ops: MEMOPS_ALL,
                                    },
                                )
                                .unwrap();
                        } else if mr.start >= pr.range.start.as_u64()
                            && pr.range.end.as_u64() < mr.end
                        {
                            engine
                                .create_root_region(
                                    domain,
                                    AccessRights {
                                        start: mr.start as usize,
                                        end: pr.range.end.as_usize(),
                                        resource: ResourceKind::ram_with_all_partitions(),
                                        ops: MEMOPS_ALL,
                                    },
                                )
                                .unwrap();
                        }
                    }
                    MemoryRange::SinglePhysContigRange(_) => panic!("not supported"),
                },
                MemoryRegionKind::Reserved => {
                    if let Err(e) = engine.create_root_region(
                        domain,
                        AccessRights {
                            start: mr.start as usize,
                            end: mr.end as usize,
                            resource: ResourceKind::Device,
                            ops: MEMOPS_ALL,
                        },
                    ) {
                        log::error!("create_root_region failed with {:?}", e);
                        panic!("error creating root region");
                    }
                }
            }
        }

        //give dom0 access to all device ranges : devices are in gaps of boot mem map
        let mut prev = &manifest.get_boot_mem_regions()[0];
        for cur in manifest.get_boot_mem_regions().iter().skip(1) {
            if cur.start < prev.end {
                panic!(
                    "weird, unsorted entry: 0x{:x} to 0x{:x}",
                    cur.start, prev.end
                );
            }
            //no gap -> continue
            if prev.end == cur.start {
                prev = cur;
                continue;
            }

            //TODO: In the future, we just leave a whole in the addr space (right now there is a bug/issue, were creating
            //the root region with no ops, it will just be filled with RAM in the remapper)
            //Thus we map IOMMU as read only for now
            //Exclude IOMMU
            let device_start = prev.end;
            let device_end = cur.start;
            if manifest.iommu_hpa != 0
                && manifest.iommu_hpa >= device_start
                && manifest.iommu_hpa < device_end
            {
                //edge case
                assert!(manifest.iommu_hpa != device_start);
                //mem before iommu
                let prefix_size = manifest.iommu_hpa - device_start;
                //mem after iommu. The -PAGE_SIZE excludes the IOMMU itself
                let suffix_size = (device_end - device_start) - prefix_size - PAGE_SIZE as u64;

                assert_eq!(
                    prefix_size + suffix_size,
                    (device_end - device_start) - 0x1000
                );
                //region for prefix
                if let Err(e) = engine.create_root_region(
                    domain,
                    AccessRights {
                        start: device_start as usize,
                        end: (device_start + prefix_size) as usize,
                        resource: ResourceKind::Device,
                        ops: MEMOPS_ALL,
                    },
                ) {
                    log::error!("create_root_region for device prefix failed with {:?}", e);
                    panic!("error creating root region");
                }
                //blocked iommu region
                log::info!(
                    "Blocked IOMMU part start 0x{:013x} end 0x{:013x}",
                    manifest.iommu_hpa,
                    manifest.iommu_hpa as usize + PAGE_SIZE
                );

                if let Err(e) = engine.create_root_region(
                    domain,
                    AccessRights {
                        start: manifest.iommu_hpa as usize,
                        end: manifest.iommu_hpa as usize + PAGE_SIZE,
                        resource: ResourceKind::Device,
                        ops: MemOps::READ,
                    },
                ) {
                    log::error!("create_root_region for device prefix failed with {:?}", e);
                    panic!("error creating root region");
                }
                //region for suffix
                if let Err(e) = engine.create_root_region(
                    domain,
                    AccessRights {
                        start: manifest.iommu_hpa as usize + PAGE_SIZE,
                        end: device_end as usize,
                        resource: ResourceKind::Device,
                        ops: MEMOPS_ALL,
                    },
                ) {
                    log::error!("create_root_region for device prefix failed with {:?}", e);
                    panic!("error creating root region");
                }
            } else {
                if let Err(e) = engine.create_root_region(
                    domain,
                    AccessRights {
                        start: device_start as usize,
                        end: device_end as usize,
                        resource: ResourceKind::Device,
                        ops: MEMOPS_ALL,
                    },
                ) {
                    log::error!("create_root_region failed with {:?}", e);
                    panic!("error creating root region");
                }
            }

            prev = cur;
        }

        //if we are here, we have created all capas for the core memory that should get used by dom0
        //now we can create the remappings

        //create mappings for dom0 core memory

        let dom0_additional_colors = match &manifest.remaining_dom_memory {
            MemoryRange::ColoredRange(cr) => {
                let mut bm = PartitionBitmap::new();
                for color_id in cr.first_color..(cr.first_color + cr.color_count) {
                    bm.set(color_id as usize, true);
                }
                bm
            }
            MemoryRange::SinglePhysContigRange(_) => todo!(),
            MemoryRange::AllRamRegionInRange(_) => todo!(),
        };

        //luca: using are contig range makes stuff easier here. This is not a hard requirement,
        //just saves some implementation effort
        let dom0_core_colors: (usize, usize) = dom0_partititons
            .try_into()
            .expect("dom0 core colors not contiguous");

        log::info!(
            "calling map compactified for dom0 core colors {:#?}",
            dom0_core_colors
        );
        state
            .map_compactified_range(
                domain,
                dom0_core_colors,
                true,
                0,
                engine
                    .get_domain_regions(domain)
                    .expect("failed to get domain regions"),
            )
            .expect("map compactified for core mem failed");

        if manifest.dom0_gpa_additional_mem != 0 {
            let additional_mem_start_gpa = manifest.dom0_gpa_additional_mem;
            log::info!(
                "Manifest specifies start GPA for additional mem: 0x{:013x}",
                manifest.dom0_gpa_additional_mem
            );
            let dom0_additional_colors: (usize, usize) = dom0_additional_colors
                .try_into()
                .expect("dom0 additional colors not contiguous");
            log::info!(
                "calling map compactified for dom0 additional_colors {:#?}",
                dom0_additional_colors
            );
            state
                .map_compactified_range(
                    domain,
                    dom0_additional_colors,
                    false,
                    additional_mem_start_gpa,
                    engine.get_domain_regions(domain).unwrap(),
                )
                .expect("map compactified for additional mem failed");
        };

        log::info!("Created all regions. Calling apply_updates...");
        //TODO: call the platform?
        Self::apply_updates(state, &mut engine);
        // Save the initial domain.
        let mut initial_domain = INITIAL_DOMAIN.lock();
        *initial_domain = Some(domain);

        // Create and save the I/O domain.
        let io_domain = engine.create_io_domain(domain).unwrap();
        let mut initial_io_domain = IO_DOMAIN.lock();
        *initial_io_domain = Some(io_domain);

        log::info!("Calling start_domain_on_core...");
        // TODO: taken from part of init_vcpu.
        engine
            .start_domain_on_core(domain, cpuid())
            .expect("Failed to start initial domain on core");
        log::info!("done!");
        domain
    }

    fn start_initial_domain(state: &mut T) -> Handle<Domain> {
        let mut dom = INITIAL_DOMAIN.lock().unwrap();
        let mut engine = Self::lock_engine(state, &mut dom);
        engine.start_domain_on_core(dom, cpuid()).unwrap();
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
            while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
                next_capa = next_next_capa;
                log::info!(" - {}", info);
            }
            log::info!(
                "tracker: {}",
                engine.get_domain_regions(domain).expect("Invalid domain")
            );
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

    fn do_set_core(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: usize,
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
        if cores & (1 << core) == 0 {
            return Err(CapaError::InvalidCore);
        }
        let domain = engine.get_domain_capa(*current, domain)?;
        state.set_core(&mut engine, &domain, core, idx, value)
    }

    fn do_get_core(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: usize,
        idx: usize,
    ) -> Result<usize, CapaError> {
        let mut engine = Self::lock_engine(state, current);
        // Check the core is valid.
        let cores = engine.get_child_permission(
            *current,
            domain,
            permission::PermissionIndex::AllowedCores,
        )?;
        if cores & (1 << core) == 0 {
            return Err(CapaError::InvalidCore);
        }
        let domain = engine.get_domain_capa(*current, domain)?;
        state.get_core(&mut engine, &domain, core, idx)
    }

    fn do_get_all_gp(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let core_map = engine.get_child_permission(
            *current,
            domain,
            permission::PermissionIndex::AllowedCores,
        )?;
        if core_map & (1 << core) == 0 {
            return Err(CapaError::InvalidCore);
        }
        let domain = engine.get_domain_capa(*current, domain)?;
        let result: &mut [usize] = &mut [0; 15];
        state.get_core_gp(&mut engine, &domain, core, result)?;
        state.dump_in_gp(&mut engine, current, cpuid(), &result)?;
        Ok(())
    }

    fn do_write_fields(
        state: &mut T,
        current: &mut Handle<Domain>,
        domain: LocalCapa,
        core: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let core_map = engine.get_child_permission(
            *current,
            domain,
            permission::PermissionIndex::AllowedCores,
        )?;
        if core_map & (1 << core) == 0 {
            return Err(CapaError::InvalidCore);
        }
        let mut values: [(usize, usize); 6] = [(0, 0); 6];
        state.extract_from_gp(&mut engine, current, cpuid(), &mut values)?;
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
        let core = cpuid();
        let mut engine = Self::lock_engine(state, current);
        //TODO: fix that.
        let capa = engine.seal(*current, core, domain)?;
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
        serialized_mem_ops: usize,
        raw_data_handle: usize,
    ) -> Result<(LocalCapa, LocalCapa), CapaError> {
        //Get Access to additional payload data
        let data_handle = DataTransferPoolHandle::deserialize(raw_data_handle)?;
        let data = state.consume_data_from_domain(current, data_handle)?;
        let serialized_rk_data = &data.get_data()[..ResourceKind::SERIALIZED_SIZE];

        //deserialize additional payload data
        let resource_kind = ResourceKind::dom0_deserialization(serialized_rk_data)?;

        let prot = MemOps::from_usize(serialized_mem_ops)?;
        if prot.intersects(MEMOPS_EXTRAS) {
            log::error!("Invalid prots for segment region {:?}", prot);
            return Err(CapaError::InvalidOperation);
        }

        //process data
        let mut engine = Self::lock_engine(state, current);
        let access = AccessRights {
            start,
            end,
            resource: resource_kind,
            ops: prot,
        };
        log::info!(
            "do_segment_region: is_shared?: {}, access: {:x?}",
            is_shared,
            access
        );
        let to_send = if is_shared {
            match engine.alias_region(*current, capa, access) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("do_segment_region: alias_region failed with {:?}", e);
                    return Err(e);
                }
            }
        } else {
            match engine.carve_region(*current, capa, access) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("do_segment_region: carve_region failed with {:?}", e);
                    return Err(e);
                }
            }
        };
        let to_revoke = match engine.create_revoke_capa(*current, to_send) {
            Ok(v) => v,
            Err(e) => {
                log::error!("do_segment_region: create_revoke_capa failed with {:?}", e);
                return Err(e);
            }
        };
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
        match engine.get_region_capa(*current, capa)? {
            Some(_) => return Err(CapaError::InvalidCapa),
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
        serialized_flags: usize,
        raw_data_handle: usize,
    ) -> Result<(), CapaError> {
        //access additional data
        //Get Access to additional payload data
        let data_handle = DataTransferPoolHandle::deserialize(raw_data_handle)?;
        let data = state.consume_data_from_domain(current, data_handle)?;

        /* TODO: luca: don't need resouce kind here, this is already encoded in the capa
         */
        let serialized_rk_data = &data.get_data()[0..ResourceKind::SERIALIZED_SIZE];

        let mut engine = Self::lock_engine(state, current);
        let flags = MemOps::from_usize(serialized_flags)?;
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
            state.map_region(
                &mut engine,
                target,
                GuestPhysAddr::new(alias),
                HostPhysAddr::new(region_info.start),
                region_info.end - region_info.start,
                repeat,
            )?;
        }
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    fn do_enumerate(
        state: &mut T,
        current: &mut Handle<Domain>,
        token: NextCapaToken,
    ) -> Option<(CapaInfo, NextCapaToken)> {
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
        cpuid: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        engine.switch(*current, cpuid, capa)?;
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
        core: usize,
    ) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let domain = engine.get_domain_capa(*current, domain)?;
        let cores = engine.get_domain_permission(domain, permission::PermissionIndex::AllowedCores);
        let remapped_core = T::remap_core(core);
        if remapped_core > T::max_cpus() || (1 << remapped_core) & cores == 0 {
            log::error!(
                "Attempt to set context on unallowed core {} max_cpus {} cores: 0x{:x}",
                remapped_core,
                T::max_cpus(),
                cores
            );
            return Err(CapaError::InvalidCore);
        }
        T::create_context(state, engine, *current, domain, remapped_core)?;
        return Ok(());
    }

    //this handles the vmcalls
    //at some point all of the exchanged data needs to fit into registers
    fn do_monitor_call(
        state: &mut T,
        domain: &mut Handle<Domain>,
        call: usize,
        args: &[usize; 6],
        res: &mut [usize; 6],
    ) -> Result<bool, CapaError> {
        match call {
            calls::CREATE_DOMAIN => {
                log::trace!("Create domain on core {}", cpuid());
                let capa = Self::do_create_domain(state, domain)?;
                res[0] = capa.as_usize();
                return Ok(true);
            }
            calls::SEAL_DOMAIN => {
                log::trace!("Seal Domain on core {}", cpuid());
                let capa = Self::do_seal(state, domain, LocalCapa::new(args[0]))?;
                res[0] = capa.as_usize();
                return Ok(true);
            }
            calls::SEND => {
                log::trace!("Send on core {}", cpuid());
                Self::do_send(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LocalCapa::new(args[1]),
                )?;
                return Ok(true);
            }
            calls::SEND_REGION_REPEAT | calls::SEND_REGION => {
                log::trace!("Send region on core {}", cpuid());
                Self::do_send_region(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LocalCapa::new(args[1]),
                    args[2],
                    call == calls::SEND_REGION_REPEAT,
                    args[3],
                    args[4],
                    args[5],
                )?;
                // The API expects the revocation handle in the first arg.
                res[0] = args[0];
                return Ok(true);
            }
            calls::SEGMENT_REGION => {
                log::trace!("Segment region on core {}", cpuid());
                let (to_send, to_revoke) = Self::do_segment_region(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    args[1] != 0,
                    args[2],
                    args[3],
                    args[4],
                    args[5],
                )?;
                res[0] = to_send.as_usize();
                res[1] = to_revoke.as_usize();
                return Ok(true);
            }
            // There are no aliases on riscv so we just ignore the alias info.
            calls::REVOKE | calls::REVOKE_ALIASED_REGION => {
                log::trace!("Revoke on core {}", cpuid());
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
                log::trace!("Enumerate on core {}", cpuid());
                if let Some((info, next)) =
                    Self::do_enumerate(state, domain, NextCapaToken::from_usize(args[0]))
                {
                    let (v1, v2, v3, serialized_rk) = info.serialize();
                    res[0] = v1;
                    res[1] = v2;
                    res[2] = v3 as usize;
                    res[5] = next.as_usize();
                    match &info {
                        CapaInfo::Region { .. } | CapaInfo::RegionRevoke { .. } => {
                            let data_handle = Self::do_create_domain_data_to_domain(
                                state,
                                domain,
                                &serialized_rk,
                            )?;
                            res[3] = data_handle.serialize() as usize;
                        }
                        CapaInfo::Management { .. }
                        | CapaInfo::Channel { .. }
                        | CapaInfo::Switch { .. } => {
                            res[3] = DataTransferPoolHandle::invalid().serialize() as usize
                        }
                    }
                } else {
                    res[5] = 0;
                }
                return Ok(true);
            }
            calls::SWITCH => {
                log::trace!(
                    "Switch on core {} from {} with capa {}",
                    cpuid(),
                    domain.idx(),
                    args[0]
                );
                Self::do_switch(state, domain, LocalCapa::new(args[0]), cpuid())?;
                return Ok(false);
            }
            calls::EXIT => {
                todo!("Exit called")
            }
            calls::DEBUG => {
                todo!("Debug implement")
            }
            calls::CONFIGURE => {
                log::trace!("Configure on core {}", cpuid());
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
                    T::remap_core(args[1]),
                    args[2],
                    args[3],
                )?;
                return Ok(true);
            }
            calls::GET_CONFIG_CORE => {
                log::trace!("Get config core on core {}", cpuid());
                let value = Self::do_get_core(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    T::remap_core(args[1]),
                    args[2],
                )?;
                res[0] = value;
                return Ok(true);
            }
            calls::ALLOC_CORE_CONTEXT => {
                Self::do_init_child_context(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    T::remap_core(args[1]),
                )?;
                return Ok(true);
            }
            calls::READ_ALL_GP => {
                log::trace!("Read all gp on core {}", cpuid());
                Self::do_get_all_gp(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    T::remap_core(args[1]),
                )?;
                return Ok(false);
            }
            calls::WRITE_ALL_GP => {
                todo!("Implement!!!");
            }
            calls::WRITE_FIELDS => {
                log::trace!("Write fields on core {}", cpuid());
                Self::do_write_fields(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    T::remap_core(args[1]),
                )?;
                return Ok(true);
            }
            calls::SELF_CONFIG => {
                todo!("Implement!!!");
            }
            /* calls::REVOKE_ALIASED_REGION => {
                log::trace!("Revoke aliased region on core {}", cpuid());
                Self::do_revoke_region(
                    state,
                    domain,
                    LocalCapa::new(args[0]),
                    LocalCapa::new(args[1]),
                    args[2],
                    args[3],
                )
                .unwrap();
                return Ok(true);
            } */
            calls::SERIALIZE_ATTESTATION => {
                let written = Self::do_serialize_attestation(state, domain, args[0], args[1])?;
                res[0] = written;
                return Ok(true);
            }
            calls::GET_HPAS => {
                let start_gpa = GuestPhysAddr::new(args[0]);
                let size = args[1];
                let (start_hpa, end_hpa) = Self::do_get_hpas(state, domain, start_gpa, size)?;
                match (start_hpa, end_hpa) {
                    (Some(start_hpa), Some(end_hpa)) => {
                        res[0] = start_hpa.as_usize();
                        res[1] = end_hpa.as_usize();
                        Ok(true)
                    }
                    _ => {
                        log::info!(
                            "GET_HPAS: failed to translate both GPAs: {:x?} {:x?}",
                            start_hpa,
                            end_hpa
                        );
                        Err(CapaError::InvalidValue)
                    }
                }
            }
            calls::SEND_DATA => {
                let raw_handle = args[0];
                let specified_payload_bytes = args[1];
                let mark_finished = args[2];
                let raw_data = &args[3..6];
                let raw_max_size = raw_data.len() * mem::size_of::<usize>();
                /*log::info!(
                    "SEND_DATA: raw_data 0x{:x?} size {}, value at idx 0 is {:x}",
                    raw_data,
                    specified_payload_bytes,
                    raw_data[0],
                );*/
                if specified_payload_bytes > raw_max_size {
                    //TODO: better error value
                    return Err(CapaError::InvalidOperation);
                }
                //TODO: stuff breaks here
                let data: &[u8] = unsafe {
                    slice::from_raw_parts(raw_data.as_ptr() as *const u8, specified_payload_bytes)
                };
                /*log::info!(
                    "SEND_DATA tyche call handler: raw_handle {}, mark_finished? {}, data as u8 0x{:x?}",
                    raw_handle,
                    mark_finished,
                    data,
                );*/
                match Self::do_store_domain_data(state, domain, raw_handle, data, mark_finished) {
                    Ok(handle) => {
                        res[0] = handle.serialize() as usize;
                        //log::info!("SEND_DATA: returning handle {}", res[0]);
                        return Ok(true);
                    }
                    Err(e) => {
                        log::error!("SEND_DATA: failed");
                        return Err(e);
                    }
                }
            }
            calls::GET_DATA => {
                let raw_handle = args[0];
                let (chunck, actual_size, remaining) =
                    Self::do_copy_data_to_domain(state, domain, raw_handle)?;
                /*log::info!(
                    "GET DATA : raw_handle {:?} , data_chunck {:x?}, remaining {}, actual_size {}",
                    raw_handle,
                    chunck,
                    remaining,
                    actual_size
                );*/

                res[0] = remaining;
                res[1] = actual_size;
                assert!(chunck.len() % mem::size_of::<usize>() == 0);
                let data_as_usize = unsafe {
                    slice::from_raw_parts(
                        chunck.as_ptr() as *const usize,
                        chunck.len() / mem::size_of::<usize>(),
                    )
                };
                res[2] = data_as_usize[0];
                res[3] = data_as_usize[1];
                res[4] = data_as_usize[2];
                Ok(true)
            }
            calls::PV_IOMMU => {
                if domain.idx() != 0 {
                    log::error!("Domain {:?} tried to access IOMMU", domain);
                    return Err(CapaError::InvalidPermissions);
                }
                let raw_command = args[0];
                let cmd = PvIOMMUCommand::from_raw(raw_command).map_err(|_| {
                    log::info!("CONFIGURE_IOMMU invalid command {}", raw_command);
                    CapaError::CouldNotDeserializeInfo
                })?;
                let raw_buf = &args[1..6];
                let raw_buf_u8 = unsafe {
                    slice::from_raw_parts(
                        raw_buf.as_ptr() as *const u8,
                        raw_buf.len() * mem::size_of::<usize>(),
                    )
                };
                match Self::do_pv_iommu_cmd(cmd, raw_buf_u8, state, domain) {
                    Ok(res_data) => {
                        //copy result data
                        for (idx, v) in res_data.get_raw().iter().enumerate() {
                            res[idx] = *v;
                        }
                    }
                    Err(e) => {
                        log::error!("do_pv_iommu_cmd failed with {:?}", e);
                        return Err(e);
                    }
                }

                Ok(true)
            }
            _ => {
                log::info!("do_monitor_call : operation failed : call number {}", call);
                return Err(CapaError::InvalidOperation);
            }
        }
    }

    fn do_handle_violation(state: &mut T, current: &mut Handle<Domain>) -> Result<(), CapaError> {
        let mut engine = Self::lock_engine(state, current);
        let core = cpuid();
        state.context_interrupted(current, core);
        engine.handle_violation(*current, core)?;
        Self::apply_updates(state, &mut engine);
        Ok(())
    }

    /// Look up the HPAs for `start` and `start+length`
    /// With coloring the HPA space is not contiguous but combined with the allowed
    /// colors a start and end hpa uniquely identify a memory range. This is also
    /// the representation that we use in the CPA engine
    fn do_get_hpas(
        state: &mut T,
        current: &mut Handle<Domain>,
        start: GuestPhysAddr,
        length: usize,
    ) -> Result<(Option<HostPhysAddr>, Option<HostPhysAddr>), CapaError> {
        let start_hpa = state.get_hpa(*current, start);
        let end_hpa = state.get_hpa(*current, start + length);
        Ok((start_hpa, end_hpa))
    }

    fn consume_domain_data(
        state: &mut T,
        current: &mut Handle<Domain>,
        handle: DataTransferPoolHandle,
    ) -> Result<DataPoolEntry, CapaError> {
        state.consume_data_from_domain(current, handle)
    }

    fn do_create_domain_data_to_domain(
        state: &mut T,
        current: &mut Handle<Domain>,
        data: &[u8],
    ) -> Result<DataTransferPoolHandle, CapaError> {
        state.create_new_domain_data_entry(current, DataPoolDirection::ToDomain(data))
    }

    fn do_copy_data_to_domain(
        state: &mut T,
        current: &mut Handle<Domain>,
        raw_data_handle: usize,
    ) -> Result<([u8; DataTransferPool::TO_DOMAIN_CHUNCK_SIZE], usize, usize), CapaError> {
        let data_handle = DataTransferPoolHandle::deserialize(raw_data_handle)?;
        state.copy_data_to_domain(current, data_handle)
    }

    /// If called with invalid handle we will create a new one, otherwise we append to
    /// the corresponding entry
    fn do_store_domain_data(
        state: &mut T,
        current: &mut Handle<Domain>,
        raw_data_handle: usize,
        data: &[u8],
        mark_finished: usize,
    ) -> Result<DataTransferPoolHandle, CapaError> {
        //either create new handle or deserialize the existing one
        let data_handle =
            if raw_data_handle == DataTransferPoolHandle::invalid().serialize() as usize {
                state.create_new_domain_data_entry(current, DataPoolDirection::FromDomain)?
            } else {
                DataTransferPoolHandle::deserialize(raw_data_handle).map_err(|e| {
                    log::error!(
                        "Failed to build data handle from value {} : {:?}",
                        raw_data_handle,
                        e
                    );
                    CapaError::CouldNotDeserializeInfo
                })?
            };
        //store
        state.store_domain_data(current, data_handle, data, mark_finished != 0)?;
        Ok(data_handle)
    }

    /// Wrapper to execute cmd in paravirt iommu driver
    fn do_pv_iommu_cmd(
        cmd: PvIOMMUCommand,
        raw_buf: &[u8],
        state: &mut T,
        current: &mut Handle<Domain>,
    ) -> Result<PvIommuResult, CapaError> {
        match state.execute_pv_iommu_cmd(cmd, raw_buf, current) {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("execute_pv_iommu_cmd for cmd {} failed: {:?}", cmd, e);
                Err(CapaError::PvIommuError)
            }
        }
    }

    fn apply_updates(state: &mut T, engine: &mut MutexGuard<CapaEngine>) {
        while let Some(update) = engine.pop_update() {
            match update {
                capa_engine::Update::PermissionUpdate { domain, core_map } => {
                    let core_id = cpuid();
                    log::trace!(
                        "cpu {} processes PermissionUpdate with core_map={:b}",
                        core_id,
                        core_map
                    );
                    // Do we have to process updates
                    //unsafe { asm!("ud2") };
                    if T::update_permission(domain, engine) {
                        let mut core_count = core_map.count_ones() as usize;
                        if (1 << core_id) & core_map != 0 {
                            state.platform_shootdown(&domain, core_id, true);
                        } else {
                            // We will wait on the barrier.
                            core_count += 1;
                        }
                        // Prepare the update.
                        T::prepare_notify(&domain, core_count);
                        for core in BitmapIterator::new(core_map) {
                            if core == core_id {
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
                capa_engine::Update::RevokeDomain { domain } => T::revoke_domain(domain),
                capa_engine::Update::CreateDomain { domain } => T::create_domain(domain),
                capa_engine::Update::Switch {
                    domain,
                    return_capa,
                    core,
                } => {
                    let mut core_updates = CORE_UPDATES[core as usize].lock();
                    core_updates
                        .push(CoreUpdate::Switch {
                            domain,
                            return_capa,
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
    fn apply_core_updates(state: &mut T, current: &mut Handle<Domain>, core_id: usize) {
        let core = cpuid();
        let mut update_queue = CORE_UPDATES[core_id].lock();
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
        }
    }
}
