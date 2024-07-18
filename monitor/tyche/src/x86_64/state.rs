use core::sync::atomic::{AtomicBool, Ordering};

use capa_engine::config::{NB_CORES, NB_DOMAINS, NB_REMAP_REGIONS};
use capa_engine::context::{RegisterContext, RegisterState};
use capa_engine::{
    CapaEngine, CapaError, Domain, GenArena, Handle, LocalCapa, MemOps, PermissionIterator,
    Remapper, ResourceKind,
};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::ioptmapper::{PAGE_MASK, PAGE_SIZE};
use mmu::mapper::Mapper;
use mmu::memory_coloring::color_to_phys::{ColorToPhys, MemoryRegionKind};
use mmu::memory_coloring::ActiveMemoryColoring;
use mmu::{EptMapper, FrameAllocator, IoPtFlag, IoPtMapper};
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::{EptEntryFlags, EptMemoryType};
use vmx::fields::VmcsField;
use vmx::{ActiveVmcs, Vmxon};
use vtd::Iommu;

use super::context::Contextx86;
use super::vmx_helper::{dump_host_state, load_host_state};
use crate::allocator::allocator;
use crate::monitor::PlatformState;
use crate::rcframe::{RCFrame, RCFramePool, EMPTY_RCFRAME};
use crate::statics::get_manifest;
use crate::sync::Barrier;

/// VMXState encapsulates the vmxon and current vcpu.
/// The vcpu is subject to changes, but the vmxon remains the same
/// for the entire execution.
pub struct VmxState {
    pub vcpu: ActiveVmcs<'static>,
    pub vmxon: Vmxon,
    pub manifest: &'static Manifest,
}

/// Static values
pub static DOMAINS: [Mutex<DataX86>; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
pub static RC_VMCS: Mutex<RCFramePool> =
    Mutex::new(GenArena::new([EMPTY_RCFRAME; { NB_DOMAINS * NB_CORES }]));
pub static CONTEXTS: [[Mutex<Contextx86>; NB_CORES]; NB_DOMAINS] =
    [EMPTY_CONTEXT_ARRAY; NB_DOMAINS];
pub static IOMMU: Mutex<Iommu> =
    Mutex::new(unsafe { Iommu::new(HostVirtAddr::new(usize::max_value())) });
pub const FALSE: AtomicBool = AtomicBool::new(false);
pub static TLB_FLUSH_BARRIERS: [Barrier; NB_DOMAINS] = [Barrier::NEW; NB_DOMAINS];
pub static TLB_FLUSH: [AtomicBool; NB_DOMAINS] = [FALSE; NB_DOMAINS];

// —————————————————————————————— Empty values —————————————————————————————— //
const EMPTY_CONTEXT_ARRAY: [Mutex<Contextx86>; NB_CORES] = [EMPTY_CONTEXT; NB_CORES];
const EMPTY_CONTEXT: Mutex<Contextx86> = Mutex::new(Contextx86 {
    regs: RegisterContext {
        dirty: capa_engine::context::Cache { bitmap: 0 },
        state_16: RegisterState::new(),
        state_32: RegisterState::new(),
        state_64: RegisterState::new(),
        state_nat: RegisterState::new(),
        state_gp: RegisterState::new(),
    },
    interrupted: false,
    vmcs: Handle::<RCFrame>::new_invalid(),
});
const EMPTY_DOMAIN: Mutex<DataX86> = Mutex::new(DataX86 {
    ept: None,
    ept_old: None,
    iopt: None,
    remapper: Remapper::new(),
});

/// Domain data on x86
pub struct DataX86 {
    pub ept: Option<HostPhysAddr>,
    pub ept_old: Option<HostPhysAddr>,
    pub iopt: Option<HostPhysAddr>,
    pub remapper: Remapper<NB_REMAP_REGIONS>,
}

pub type StateX86 = VmxState;

/// Maps `ResourceKind::RAM` according to the color attribute. `ResourceKind::Device` are passed through mapped
/// # Arguments
/// - `permission_builder` : build page table entry permission flags for the mappings
fn color_aware_mapper<F: Fn(&MemOps,&ResourceKind)->Result<u64,()>>(
    mapper: &mut impl Mapper,
    permission_iter: PermissionIterator,
    domain: &MutexGuard<'static, DataX86>,
    permission_builder : F,
) {
    let allocator = allocator();

    let mut next_blocked_iter = domain
        .remapper
        .remap(permission_iter.clone())
        .filter(|v| match v.resource_kind {
            ResourceKind::RAM(_) => false,
            ResourceKind::Device => true,
        });
    let mut next_blocked = next_blocked_iter.next();

    for dr in domain.remapper.remap(permission_iter.clone()) {
        log::info!(
            "device region 0x{:013x} 0x{:013x}",
            dr.hpa,
            dr.hpa + dr.size
        );
    }

    let mut next_ram_gpa = 0;
    //skip over device regions that have smaller addr than first ram region
    let first_ram_region = domain
        .remapper
        .remap(permission_iter.clone())
        .filter(|v| {
            ResourceKind::same_kind(&v.resource_kind, &ResourceKind::ram_with_all_partitions())
        })
        .next()
        .expect("no ram regions");
    while let Some(nb) = next_blocked.as_ref() {
        if nb.hpa > first_ram_region.hpa {
            break;
        }
        next_ram_gpa += nb.size;
        next_blocked = next_blocked_iter.next();
    }
    log::info!("First ram region is {:x?}", &first_ram_region);
    log::info!("First blocking dev region is {:x?}", &next_blocked);
    log::info!("Initial next_ram_gpa value is 0x{:x}", &next_ram_gpa);

    let boot_mem_region_gib = get_manifest()
        .get_boot_mem_regions()
        .iter()
        .filter(|v| v.kind == MemoryRegionKind::UseableRAM)
        .map(|v| v.end - v.start)
        .sum::<u64>() as f64
        / ((1 << 30) as f64);
    log::info!("boot mem regions can represent {} GiB", boot_mem_region_gib);
    let mut mapped_ram_bytes = 0;
    let mut mapped_device_bytes = 0;
    //total number of contig phys ranges that we used to back the GPA RAM space
    let mut total_ram_range_count = 0;
    for (_, range) in domain.remapper.remap(permission_iter).enumerate() {
        
        let flags = permission_builder(&range.ops, &range.resource_kind).expect("failed to build flags");
        /* Observations/Assumptions:
         * The results of the iterator are sorted, i.e. we go through the address space "left to right".
         * With partititions, a memory range might be smaller that its actually physical bounds, however
         * it cannot be larger. Thus, we cannot end up in the situation where we want to map an identity
         * mapped device but have already used that part of the address space for one of the preceedign
         * mappings
         *
         * TODO: preserve order when adding new colors later on
         */
        let resource_kind = range.resource_kind;
        match resource_kind {
            capa_engine::ResourceKind::RAM(partitions_ids) => {
                let color_to_phys = ColorToPhys::new(
                    get_manifest().get_boot_mem_regions(),
                    ActiveMemoryColoring {},
                    partitions_ids,
                    Some((range.hpa, range.hpa + range.size)),
                );

                let mut chunk_idx = 0;

                //TODO:have not yet implemented support for multiple repeat
                assert!(range.repeat == 1);

                log::info!(
                    "processing start 0x{:013x}, end 0x{:013x}, size 0x{:013x}, type RAM",
                    range.hpa,
                    range.hpa + range.size,
                    range.size
                );
                color_to_phys.visit_all_as_ranges(|partition_chunk| {
                 //figure out amout of bytes we can map before hitting the next range blocked for a device
                 let mut remaining_chunk_bytes = partition_chunk.size();
                 //log::info!("chunck {:x?}. size 0x{:x}", &partition_chunk, remaining_chunk_bytes);
                 while remaining_chunk_bytes > 0 {
                     let map_size;
                     let mut advance_next_blocked = false;
                     match &next_blocked {
                         Some(next_blocked) => {
                             //for device mem we need to compare gour gpa with hpa, because we will passtrhough/identity map them
                             assert!(next_ram_gpa <= next_blocked.hpa);
                             let bytes_until_blocked = next_blocked.hpa - next_ram_gpa;
                             assert!(bytes_until_blocked > 0, "bytes untill blocked was 0. next_blocked.hpa = 0x{:x}, next_ram_gpa 0x{:x}", next_blocked.hpa, next_ram_gpa);
                             if remaining_chunk_bytes < bytes_until_blocked {
                                 map_size = remaining_chunk_bytes;
                             } else {
                                 advance_next_blocked = true;
                                 map_size = bytes_until_blocked;
                             }
                         }
                         None => {
                             //No more blocked ranges -> can map everything
                             map_size = remaining_chunk_bytes;
                             //log::info!("no blocking dev path, mapping whole 0x{:x}", map_size);
                         }
                     }

                     assert_eq!(next_ram_gpa % PAGE_SIZE, 0, "next_ram_gpa is not aligned");
                     assert_eq!(map_size % PAGE_SIZE, 0, "map_size ist not aligned");
                     assert!(map_size > 0);
                     mapper.map_range(
                         allocator,
                         &GuestPhysAddr::new(next_ram_gpa),
                         &HostPhysAddr::new(partition_chunk.end - remaining_chunk_bytes),
                         map_size,
                         flags,
                     );
                     mapped_ram_bytes += map_size;
                     remaining_chunk_bytes -= map_size;
                     next_ram_gpa += map_size;
                     if advance_next_blocked {
                         let mut cur_blocked = next_blocked
                         .expect("advance_next_blocked true but next block was None");

                         //log::info!("skipping over device region at 0x{:x} to 0x{:x}", cur_blocked.hpa, cur_blocked.hpa+cur_blocked.size);

                         assert_eq!(next_ram_gpa, cur_blocked.hpa);
                         next_ram_gpa += cur_blocked
                             .size;

                         next_blocked = next_blocked_iter.next();
                        
                        //next blocked might by contiguous -> skip over next until there is a gap
                         while let Some(nb) = next_blocked {
                            if nb.hpa == (cur_blocked.hpa + cur_blocked.size) {
                                log::info!("also skipping over contiguous region 0x{:x} to 0x{:x}", nb.hpa, nb.hpa+nb.size);
                                assert_eq!(next_ram_gpa,nb.hpa);
                                next_ram_gpa += nb.size;
                                cur_blocked = nb;
                                next_blocked = next_blocked_iter.next();
                            } else {
                                break
                            }
                         }
                     }
                 } // end of "while remaining_chunk_bytes > 0"
                 chunk_idx += 1;
                total_ram_range_count += 1;

             });
            }
            // Device memory must be identity mapped, to pass through the access to the pyhsical HW
            ResourceKind::Device => {
                log::info!(
                    "processing start 0x{:013x}, end 0x{:013x}, size 0x{:013x}, type Device",
                    range.hpa,
                    range.hpa + range.size,
                    range.size
                );

                mapper.map_range(
                    allocator,
                    &GuestPhysAddr::new(range.hpa),
                    &HostPhysAddr::new(range.hpa),
                    range.size,
                    flags,
                );

                mapped_device_bytes += range.size;
            }
        } // end of "match resource_kind"
    log::info!("Mapped RAM bytes: {:0.2} GiB (0x{:x} bytes)", mapped_ram_bytes as f64 / (1<<30) as f64, mapped_ram_bytes);
    log::info!("Largest RAM GPA: 0x{:013x}", next_ram_gpa);
    log::info!("total ram range count: {}",total_ram_range_count);
    }
}

impl StateX86 {
    pub unsafe fn free_ept(ept: HostPhysAddr, allocator: &impl FrameAllocator) {
        let mapper = EptMapper::new(allocator.get_physical_offset().as_usize(), ept);
        mapper.free_all(allocator);
    }

    pub unsafe fn free_iopt(iopt: HostPhysAddr, allocator: &impl FrameAllocator) {
        let mapper = IoPtMapper::new(allocator.get_physical_offset().as_usize(), iopt);
        mapper.free_all(allocator);
    }

    fn update_iommu_page_tables(
        domain_handle: Handle<Domain>,
        engine: &mut MutexGuard<CapaEngine>,
    ) -> bool {
        let mut domain: MutexGuard<'_, DataX86> = Self::get_domain(domain_handle);
        let allocator = allocator();
        if let Some(iopt) = domain.iopt {
            unsafe { Self::free_iopt(iopt, allocator) };
            // TODO: global invalidate context cache, PASID cache, and flush the IOTLB
        }

        let iopt_root = allocator
            .allocate_frame()
            .expect("Failed to allocate I/O PT root")
            .zeroed();
        let mut iopt_mapper = IoPtMapper::new(
            allocator.get_physical_offset().as_usize(),
            iopt_root.phys_addr,
        );

      
        let permission_cb = |ops:& MemOps, kind: &ResourceKind| {
            let mut flags = IoPtFlag::empty();

            if ops.contains(MemOps::READ) {
                flags |= IoPtFlag::READ;
            }
            if ops.contains(MemOps::WRITE) {
                flags |= IoPtFlag::WRITE;
            }

            Ok(flags.bits())
        };
        let permission_iter = engine.get_domain_permissions(domain_handle).unwrap();
        color_aware_mapper(&mut iopt_mapper, permission_iter, &domain, permission_cb);

        domain.iopt = Some(iopt_root.phys_addr);

        log::info!("IOMMU PTs GPA->HPA");
        iopt_mapper.debug_range(GuestPhysAddr::new(0x101_d80_400), 0x1000);

        // Update the IOMMU (i.e. the actual hardware device)
        // TODO: @yuchen ideally we only need to change the 2nd stage page translation pointer on the
        //               context table, instead of reallocating the whole root table
        // Remap the DMA region on IOMMU
        let mut iommu = IOMMU.lock();
        //will only be != 0 if we have initialized the IOMUU. Could be more elegant with an option
        if iommu.as_ptr_mut() as usize != 0 {
            log::info!("Updating IOMMU!!!");
            let root_addr: HostPhysAddr =
                vtd::setup_iommu_context(iopt_mapper.get_root(), allocator);
            log::info!("created iommu context");
            log::info!("root_addr 0x{:016x}", root_addr.as_u64());
            /*11.4.5 in vtd spec:
             * 4KiB aligned paddr of root page table. Bits [11:0] are used for config
             * we want [11:10] set to zero to enable legacy translation mode. Qemu does not seem
             * to support scalable mode
             */
            let rtar_val = root_addr.as_u64();
            iommu.set_root_table_addr(rtar_val);
            iommu.update_root_table_addr();
            iommu.enable_translation();
            log::info!("enabled translation");
            log::info!("I/O MMU: {:?}", iommu.get_global_status());
            log::warn!("I/O MMU Fault: {:?}", iommu.get_fault_status());
        }
        false
    }

    fn update_ept_tables(
        domain_handle: Handle<Domain>,
        engine: &mut MutexGuard<CapaEngine>,
    ) -> bool {
        let mut domain = Self::get_domain(domain_handle);
        let allocator = allocator();
        if domain.ept_old.is_some() {
            panic!("We will replace an ept old that's not empty");
        }
        let ept_root = allocator
            .allocate_frame()
            .expect("Failled to allocate EPT root")
            .zeroed();
        let mut mapper = EptMapper::new(
            allocator.get_physical_offset().as_usize(),
            ept_root.phys_addr,
        );

        log::info!("\n #### Updating EPTs ####\n");
        let permission_cb = |ops:& MemOps, kind: &ResourceKind| {
            let mut flags = EptEntryFlags::empty();
            if !ops.contains(MemOps::READ) {
                match kind {
                    ResourceKind::RAM(_) => {
                        log::error!("there is a region without read permission: ");
                        return Err(());
                    }
                    //device region can have no access permissions to repreent that a device is blocked
                    //without changing the GPA layout
                    ResourceKind::Device => (),
                }
            }
            if ops.contains(MemOps::READ) {
                flags |= EptEntryFlags::READ;
            }
            if ops.contains(MemOps::WRITE) {
                flags |= EptEntryFlags::WRITE;
            }
    
            if ops.contains(MemOps::EXEC) {
                if ops.contains(MemOps::SUPER) {
                    flags |= EptEntryFlags::SUPERVISOR_EXECUTE;
                } else {
                    flags |= EptEntryFlags::USER_EXECUTE;
                }
            }
            let mut flags = flags.bits();
            match kind {
                ResourceKind::RAM(_) => flags |= EptMemoryType::WB.bits(),
                ResourceKind::Device => flags |= EptMemoryType::UC.bits(),
            }
            Ok(flags)
        };

        //luca: iterator over ranges with same memory access permissions
        let permission_iter = engine.get_domain_permissions(domain_handle).unwrap();
        color_aware_mapper(&mut mapper, permission_iter, &domain,permission_cb);

        loop {
            match TLB_FLUSH[domain_handle.idx()].compare_exchange(
                false,
                true,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(false) => break,
                _ => continue,
            }
        }

        // The core needs exclusive access before updating the domain's EPT. Otherwise, we might have
        // miss freeing some EPT roots.
        // The contexts per core will be updated in the permission change update.
        domain.ept_old = domain.ept;
        domain.ept = Some(ept_root.phys_addr);
        true
    }

    pub fn update_domain_iopt(
        domain_handle: Handle<Domain>,
        engine: &mut MutexGuard<CapaEngine>,
    ) -> bool {
        log::info!("Inside update_domain_iopt");
        Self::update_iommu_page_tables(domain_handle, engine);
        false
    }

    pub fn update_domain_ept(
        domain_handle: Handle<Domain>,
        engine: &mut MutexGuard<CapaEngine>,
    ) -> bool {
        log::info!("\n ### entering update_domain_ept ###\n");

        let ept_res = Self::update_ept_tables(domain_handle, engine);

        log::info!("\n #### Updating IOPTs ####\n");
        let iommu_res = Self::update_iommu_page_tables(domain_handle, engine);

        ept_res || iommu_res
    }

    pub fn switch_domain(
        vcpu: &mut ActiveVmcs<'static>,
        current_ctx: &mut MutexGuard<Contextx86>,
        next_ctx: &mut MutexGuard<Contextx86>,
        next_domain: MutexGuard<DataX86>,
        return_capa: LocalCapa,
    ) -> Result<(), CapaError> {
        // Safety check that both contexts have a valid vmcs.
        if current_ctx.vmcs.is_invalid() || next_ctx.vmcs.is_invalid() {
            log::error!(
                "VMCS are none during switch: curr:{:?}, next:{:?}",
                current_ctx.vmcs.is_invalid(),
                next_ctx.vmcs.is_invalid()
            );
            return Err(CapaError::InvalidSwitch);
        }

        // We have different cases:
        // 1. current(interrupted) -- interrupt --> next.
        // 2. current -- resume interrupted --> next(interrupted)
        // 3. current -- synchronous --> next
        if current_ctx.interrupted && next_ctx.interrupted {
            panic!("Two domains should never be both interrupted in a switch.");
        }
        // Case 1: copy the interrupted state.
        if current_ctx.interrupted {
            next_ctx.copy_interrupt_frame(current_ctx, vcpu).unwrap();
            // Set the return values.
            next_ctx
                .set(VmcsField::GuestRax, 0, None)
                .or(Err(CapaError::PlatformError))?;
            next_ctx
                .set(VmcsField::GuestRdi, return_capa.as_usize(), None)
                .or(Err(CapaError::PlatformError))?;
        } else if next_ctx.interrupted {
            // Case 2: do not put the return capa.
            next_ctx.interrupted = false;
        } else {
            // Case 3: synchronous call.
            next_ctx
                .set(VmcsField::GuestRax, 0, None)
                .or(Err(CapaError::PlatformError))?;
            next_ctx
                .set(VmcsField::GuestRdi, return_capa.as_usize(), None)
                .or(Err(CapaError::PlatformError))?;
        }

        // Now the logic for shared vs. private vmcs.
        if current_ctx.vmcs == next_ctx.vmcs {
            panic!("Why are the two vmcs the same?");
        }
        current_ctx.load(vcpu);

        // NOTE; it seems on hardware we need to save and restore the host context, but we don't know
        // why yet, we need further invesdigation to be able to optimise this.
        let mut values: [usize; 13] = [0; 13];
        dump_host_state(vcpu, &mut values).expect("Couldn't save host context");

        // Configure state of the next TD
        next_ctx.switch_flush(&RC_VMCS, vcpu);
        vcpu.set_ept_ptr(HostPhysAddr::new(
            next_domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
        ))
        .expect("Failed to update EPT");
        load_host_state(vcpu, &mut values).expect("Couldn't save host context");
        Ok(())
    }
}
