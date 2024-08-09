use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use capa_engine::config::{NB_COMPACT_REMAPS, NB_CORES, NB_DOMAINS, NB_SIMPLE_REMAPS};
use capa_engine::context::{RegisterContext, RegisterState};
use capa_engine::{
    CapaEngine, CapaError, Domain, GenArena, Handle, LocalCapa, MemOps, Remapper, ResourceKind,
};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::mapper::Mapper;
use mmu::memory_coloring::ActiveMemoryColoring;
use mmu::{EptMapper, FrameAllocator, IoPtFlag, IoPtMapper};
use spin::{Mutex, MutexGuard};
use stage_two_abi::Manifest;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::{EptEntryFlags, EptMemoryType};
use vmx::fields::VmcsField;
use vmx::{ActiveVmcs, Vmxon};
use vtd::{Command, Iommu};

use super::context::Contextx86;
use super::vmx_helper::{dump_host_state, load_host_state};
use crate::allocator::allocator;
use crate::data_transfer::DataTransferPool;
use crate::monitor::PlatformState;
use crate::rcframe::{RCFrame, RCFramePool, EMPTY_RCFRAME};
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
    iopt_old: None,
    remapper: Remapper::new(),
    data_transfer_pool: DataTransferPool::new(),
});

/// Domain data on x86
pub struct DataX86 {
    pub ept: Option<HostPhysAddr>,
    pub ept_old: Option<HostPhysAddr>,
    pub iopt: Option<HostPhysAddr>,
    pub iopt_old: Option<HostPhysAddr>,
    pub remapper: Remapper<NB_SIMPLE_REMAPS, NB_COMPACT_REMAPS>,
    pub data_transfer_pool: DataTransferPool,
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

    fn update_iommu_page_tables(
        domain_handle: Handle<Domain>,
        engine: &mut MutexGuard<CapaEngine>,
    ) -> bool {
        let mut domain = Self::get_domain(domain_handle);

        // luca: to my understanding IOPTs are global and not per VM. Only update sth here if we want to
        // give a device to a VM/TD. In that case, only update that devices entry. If we have given device
        // to another TD, keep the 2nd level entries for that device in sync with the TD
        // TODO: how to encode who own which device?
        // Right now, we assume all devices belong to dom0
        if domain_handle.idx() != 0 {
            return false;
        }

        if domain.iopt_old.is_some() {
            panic!("Updating IOPTs while previous one's have not been freed yet");
        }
        let allocator = allocator();

        let iopt_root = allocator
            .allocate_frame()
            .expect("Failed to allocate I/O PT root")
            .zeroed();
        let mut iopt_mapper = IoPtMapper::new(
            allocator.get_physical_offset().as_usize(),
            iopt_root.phys_addr,
        );
        let permission_iter = engine
            .get_domain_permissions(domain_handle, ActiveMemoryColoring {}, None, true)
            .unwrap();
        for range in domain
            .remapper
            .new_remap_iter(ActiveMemoryColoring {}, permission_iter)
        {
            if !range.ops.contains(MemOps::READ) {
                log::error!("there is a region without read permission: {}", range);
                continue;
            }
            iopt_mapper.map_range(
                allocator,
                &GuestPhysAddr::new(range.gpa),
                &HostPhysAddr::new(range.hpa),
                range.size,
                (IoPtFlag::READ | IoPtFlag::WRITE).bits(),
            );
        }

        // Update the IOMMU (i.e. the actual hardware device)
        // TODO: @yuchen ideally we only need to change the 2nd stage page translation pointer on the
        //               context table, instead of reallocating the whole root table
        // Remap the DMA region on IOMMU
        let mut iommu = IOMMU.lock();
        //will only be != 0 if we have initialized the IOMUU. Could be more elegant with an option
        if iommu.as_ptr_mut() as usize != 0 {
            //Enable queued invalidation if it is not already enabled
            if !iommu
                .get_global_status()
                .contains(Command::QUEUED_INVALIDATION)
            {
                if let Err(e) = iommu.enable_quid_invalidation(allocator) {
                    log::error!("Failed to enable queued invalidation: {}", e);
                    panic!("IOMMU setup failed");
                }
                log::info!("IOMMU: enabled queued invalidation");
            }

            let root_addr: HostPhysAddr =
                vtd::setup_iommu_context(iopt_mapper.get_root(), allocator);
            /*11.4.5 in vtd spec:
             * 4KiB aligned paddr of root page table. Bits [11:0] are used for config
             * we want [11:10] set to zero to enable legacy translation mode. Qemu does not seem
             * to support scalable mode
             */
            let rtar_val = root_addr.as_u64();
            iommu.set_root_table_addr(rtar_val);
            iommu.update_root_table_addr();
            iommu.enable_translation();
            if iommu.get_fault_status().have_fault() {
                log::info!("I/O MMU: {:?}", iommu.get_global_status());
                log::warn!("I/O MMU Fault: {:?}", iommu.get_fault_status());
            }

            //log::info!("IOMMU: flushing");
            if let Err(e) = iommu.full_flush_sync() {
                log::error!("IOMMU: flush failed: {}", e);
                panic!("IOMMU flush failed");
            }
            if iommu.get_fault_status().have_fault() {
                log::info!("I/O MMU: {:?}", iommu.get_global_status());
                log::warn!("I/O MMU Fault: {:?}", iommu.get_fault_status());
            }
            domain.iopt_old = domain.iopt;
            domain.iopt = Some(iopt_root.phys_addr);
        }
        true
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
        let permission_iter = engine
            .get_domain_permissions(domain_handle, ActiveMemoryColoring {}, None, true)
            .unwrap();
        let remap_iter = domain
            .remapper
            .new_remap_iter(ActiveMemoryColoring {}, permission_iter);
        let mut map_count = 0;
        for range in remap_iter {
            if !range.ops.contains(MemOps::READ) {
                //log::error!("there is a region without read permission: {}", range);
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
            let mem_type = match &range.resource_kind {
                ResourceKind::RAM(_) => EptMemoryType::WB,
                ResourceKind::Device => EptMemoryType::UC,
            };
            mapper.map_range(
                allocator,
                &GuestPhysAddr::new(range.gpa),
                &HostPhysAddr::new(range.hpa),
                range.size,
                flags.bits() | mem_type.bits(),
            );
            map_count += 1;
            if (map_count % 100) == 0 {
                log::info!("ept: processed {:06} mappings", map_count);
            }
        }

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
        Self::update_iommu_page_tables(domain_handle, engine);
        false
    }

    pub fn update_domain_ept(
        domain_handle: Handle<Domain>,
        engine: &mut MutexGuard<CapaEngine>,
    ) -> bool {
        log::info!("Updating PTs of domain {:?}", domain_handle);
        //log::info!("\n ### entering update_domain_ept ###\n");

        let ept_res = Self::update_ept_tables(domain_handle, engine);

        //log::info!("\n #### Updating IOPTs ####\n");
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
