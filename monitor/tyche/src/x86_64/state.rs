use core::cmp::min;
use core::ops::Neg;
use core::sync::atomic::{AtomicBool, Ordering};

use capa_engine::config::{NB_CORES, NB_DOMAINS, NB_REMAP_REGIONS};
use capa_engine::context::{RegisterContext, RegisterState};
use capa_engine::ResourceKind::{self, Device};
use capa_engine::{CapaEngine, CapaError, Domain, GenArena, Handle, LocalCapa, MemOps, Remapper};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::frame_allocator::PhysRange;
use mmu::ioptmapper::{PAGE_MASK, PAGE_SIZE};
use mmu::memory_coloring::color_to_phys::{self, ColorToPhys, MemoryRegion, MemoryRegionKind};
use mmu::memory_coloring::ActiveMemoryColoring;
use mmu::{EptMapper, FrameAllocator, IoPtFlag, IoPtMapper};
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::EptEntryFlags;
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

impl StateX86 {
    pub unsafe fn free_ept(ept: HostPhysAddr, allocator: &impl FrameAllocator) {
        let mapper = EptMapper::new(allocator.get_physical_offset().as_usize(), ept);
        mapper.free_all(allocator);
    }

    pub unsafe fn free_iopt(iopt: HostPhysAddr, allocator: &impl FrameAllocator) {
        let mapper = IoPtMapper::new(allocator.get_physical_offset().as_usize(), iopt);
        mapper.free_all(allocator);
    }

    pub fn update_domain_iopt(
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

        // Traverse all regions of the I/O domain and maps them into the new iopt
        for range in engine.get_domain_permissions(domain_handle).unwrap() {
            if !range.ops.contains(MemOps::READ) {
                log::error!("there is a region without read permission: {}", range);
                continue;
            }
            let gpa = range.start;
            iopt_mapper.map_range(
                allocator,
                GuestPhysAddr::new(gpa),
                HostPhysAddr::new(range.start),
                range.size(),
                IoPtFlag::READ | IoPtFlag::WRITE | IoPtFlag::EXECUTE,
            )
        }

        domain.iopt = Some(iopt_root.phys_addr);

        // Update the IOMMU
        // TODO: @yuchen ideally we only need to change the 2nd stage page translation pointer on the
        //               context table, instead of reallocating the whole root table
        // Remap the DMA region on IOMMU
        let mut iommu = IOMMU.lock();
        if iommu.get_addr() as usize != 0 {
            let root_addr: HostPhysAddr =
                vtd::setup_iommu_context(iopt_mapper.get_root(), allocator);
            iommu.set_root_table_addr(root_addr.as_u64() | (0b00 << 10)); // Set legacy mode
            iommu.update_root_table_addr();
            iommu.enable_translation();
            log::info!("I/O MMU: {:?}", iommu.get_global_status());
            log::warn!("I/O MMU Fault: {:?}", iommu.get_fault_status());
        }

        false
    }

    pub fn update_domain_ept(
        domain_handle: Handle<Domain>,
        engine: &mut MutexGuard<CapaEngine>,
    ) -> bool {
        log::info!("\n ### entering update_domain_ept ###\n");
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

        //luca: iterator over ranges with same memory access permissions
        let permission_iter = engine.get_domain_permissions(domain_handle).unwrap();

        let mut next_blocked_iter = domain
            .remapper
            .remap(permission_iter.clone())
            .filter(|v| ResourceKind::same_kind(&v.resource_kind, &ResourceKind::Device));
        let mut next_blocked = next_blocked_iter.next();

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
        for (_, range) in domain.remapper.remap(permission_iter).enumerate() {
            if !range.ops.contains(MemOps::READ) {
                log::error!("there is a region without read permission: {}", range);
                continue;
            }
            let mut flags = EptEntryFlags::READ;
            if range.ops.contains(MemOps::WRITE) {
                flags |= EptEntryFlags::WRITE;
            }

            if range.ops.contains(MemOps::EXEC) {
                if range.ops.contains(MemOps::SUPER) {
                    flags |= EptEntryFlags::SUPERVISOR_EXECUTE;
                } else {
                    flags |= EptEntryFlags::USER_EXECUTE;
                }
            }
            /*log::info!(
                "range object: Kind {:x?} start 0x{:x}, end 0x{:x}, size 0x{:x}",
                range.resource_kind,
                range.hpa,
                range.hpa + range.size,
                range.size
            );*/
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
                                        //log::info!("have blocking dev, but not hitting it, mapping 0x{:x}", map_size);
                                    } else {
                                        advance_next_blocked = true;
                                        map_size = bytes_until_blocked;
                                        //log::info!("hitting blocking dev at 0{:x}, mapping only 0x{:x} out of 0x{:x}", next_blocked.hpa, map_size, remaining_chunk_bytes);
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
                                GuestPhysAddr::new(next_ram_gpa),
                                HostPhysAddr::new(partition_chunk.end - remaining_chunk_bytes),
                                map_size,
                                flags,
                                None,
                            );
                            mapped_ram_bytes += map_size;
                            remaining_chunk_bytes -= map_size;
                            next_ram_gpa += map_size;
                            if advance_next_blocked {
                                let dev_region = next_blocked
                                .as_ref()
                                .expect("advance_next_blocked true but next block was None");

                                log::info!("skipping over device region at 0x{:x} to 0x{:x}", dev_region.hpa, dev_region.hpa+dev_region.size);

                                assert_eq!(next_ram_gpa, dev_region.hpa);
                                next_ram_gpa += dev_region
                                    .size;
                                next_blocked = next_blocked_iter.next();
                            }
                        } // end of "while remaining_chunk_bytes > 0"
                        chunk_idx += 1;
                    });
                }
                // Device memory must be identity mapped, to pass through the access to the pyhsical HW
                capa_engine::ResourceKind::Device => {
                    log::info!(
                        "processing start 0x{:013x}, end 0x{:013x}, size 0x{:013x}, type Device",
                        range.hpa,
                        range.hpa + range.size,
                        range.size
                    );
                    mapper.map_range(
                        allocator,
                        GuestPhysAddr::new(range.hpa),
                        HostPhysAddr::new(range.hpa),
                        range.size,
                        flags,
                        None,
                    );
                    mapped_device_bytes += range.size;
                }
            } // end of "match resource_kind"
        }

        log::info!("next_ram_gpa at end of mapping phase: 0x{:x}", next_ram_gpa);
        log::info!(
            "Mapped RAM {:0.2} GiB (0x{:x}) bytes)",
            mapped_ram_bytes as f64 / (1 << 30) as f64,
            mapped_ram_bytes
        );
        log::info!(
            "Mapped Device {:0.2} GiB (0x{:x} bytes)",
            mapped_device_bytes as f64 / (1 << 30) as f64,
            mapped_device_bytes
        );
        log::info!(
            "Total Mapped {:0.2} GiB (0x{:x} bytes)",
            (mapped_ram_bytes + mapped_device_bytes) as f64 / (1 << 30) as f64,
            mapped_ram_bytes + mapped_device_bytes
        );

        /*log::info!("GPA->SPA Linux load segment 00");
        mapper.debug_range(GuestPhysAddr::new(0x1000000), 3 * PAGE_SIZE);

        log::info!("GPA->SPA Linux load segment 01");
        mapper.debug_range(GuestPhysAddr::new(0x2a00000), 3 * PAGE_SIZE);

        log::info!("GPA->SPA Linux load segment 02");
        mapper.debug_range(GuestPhysAddr::new(0x323b000), 3 * PAGE_SIZE);

        log::info!("GPA->SPA Linux load segment 03");
        mapper.debug_range(GuestPhysAddr::new(0x3268000), 3 * PAGE_SIZE);

        log::info!("GPA->SPA Linux CR3");
        mapper.debug_range(GuestPhysAddr::new(0x3829000), 0x1000);
        log::info!("GPA->SPA for pages on PT walk for entry point");
        let addrs_walk_entry = [0x382d000, 0x382e000, 0x382f000];
        for x in addrs_walk_entry {
            mapper.debug_range(GuestPhysAddr::new(x), 0x1000);
        }*/

        /*log::info!("GPA->SPA for DMAR 0x000000fe_d90_000. Should be ID mapped to SPA");
        mapper.debug_range(GuestPhysAddr::new(0x000000fed90000), 0x2000);*/

        /*log::info!("GPA->SPA for qi : 0x100207000");
        mapper.debug_range(GuestPhysAddr::new(0x100207000), 0x1000);*/

        log::info!("GPA-> for pci crash");
        mapper.debug_range(GuestPhysAddr::new(0x80_000_001), 0x1000);


        /*
        //Addresses used in the vt-d interrupt remapping code
        log::info!("GPA->SPA for qi: 0x100_28a_000");
        mapper.debug_range(GuestPhysAddr::new(0x10028a000), 0x1000);

        log::info!("GPA->SPA for qi  : 0x100_28b_000");
        mapper.debug_range(GuestPhysAddr::new(0x10028b000), 0x1000);
        
        log::info!("GPA->SPA for qi  : 0x100_300_000");
        mapper.debug_range(GuestPhysAddr::new(0x100300000), 0x1000);*/

        
        /*for (mr_idx, mr) in get_manifest().get_boot_mem_regions().iter().enumerate() {
            log::info!("mr_idx {:02} excerpt of PTs for mr {:x?}", mr_idx, mr);
            mapper.debug_range(GuestPhysAddr::new(mr.start as usize), 0x1000);
            mapper.debug_range(GuestPhysAddr::new((mr.end - 0x1000) as usize), 0x1000);
        }*/

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
