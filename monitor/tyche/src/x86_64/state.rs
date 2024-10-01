use core::sync::atomic::{AtomicBool, Ordering};

use capa_engine::config::{NB_CORES, NB_DOMAINS, NB_REMAP_REGIONS};
use capa_engine::context::{RegisterContext, RegisterState};
use capa_engine::{CapaEngine, CapaError, Domain, GenArena, Handle, LocalCapa, MemOps, Remapper};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::{EptMapper, FrameAllocator, IoPtFlag, IoPtMapper};
use spin::{Mutex, MutexGuard};
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::{EptEntryFlags, PinbasedControls};
use vmx::fields::VmcsField;
use vmx::{ActiveVmcs, VmxExitReason, Vmxon};
use vtd::Iommu;

use super::context::{Contextx86, CpuidEntry, SchedInfo, MAX_CPUID_ENTRIES};
use super::perf;
use crate::allocator::allocator;
use crate::calls::{MONITOR_SUCCESS, MONITOR_SWITCH_INTERRUPTED};
use crate::monitor::PlatformState;
use crate::rcframe::{RCFrame, RCFramePool, EMPTY_RCFRAME};
use crate::sync::Barrier;

/// VMXState encapsulates the vmxon and current vcpu.
/// The vcpu is subject to changes, but the vmxon remains the same
/// for the entire execution.
pub struct VmxState {
    pub vcpu: ActiveVmcs<'static>,
    pub vmxon: Vmxon,
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

const EMPTY_CPUID_ENTRY: CpuidEntry = CpuidEntry {
    function: 0,
    index: 0,
    flags: 0,
    eax: 0,
    ebx: 0,
    ecx: 0,
    edx: 0,
};
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
    sched_info: SchedInfo {
        timed: false,
        budget: 0,
        saved_ctrls: 0,
    },
    vmcs: Handle::<RCFrame>::new_invalid(),
    launched: false,
    nb_active_cpuid_entries: 0,
    cpuid_entries: [EMPTY_CPUID_ENTRY; MAX_CPUID_ENTRIES],
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
        let mut domain = Self::get_domain(domain_handle);
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
        let permission_iter = engine.get_domain_permissions(domain_handle).unwrap();
        for range in domain.remapper.remap(permission_iter) {
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
            mapper.map_range(
                allocator,
                GuestPhysAddr::new(range.gpa),
                HostPhysAddr::new(range.hpa),
                range.size,
                flags,
            );
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

    pub fn switch_domain(
        vcpu: &mut ActiveVmcs<'static>,
        current_ctx: &mut MutexGuard<Contextx86>,
        next_ctx: &mut MutexGuard<Contextx86>,
        next_domain: MutexGuard<DataX86>,
        return_capa: LocalCapa,
        delta: usize,
    ) -> Result<(), CapaError> {
        perf::start_step(0);
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
            // If it was a timer, we need to reset the information.
            if current_ctx
                .get_current(VmcsField::VmExitReason, Some(vcpu))
                .unwrap()
                == VmxExitReason::VmxPreemptionTimerExpired as usize
                && current_ctx.sched_info.timed
            {
                current_ctx.sched_info.timed = false;
                current_ctx.sched_info.budget = 0;
                let saved = current_ctx.sched_info.saved_ctrls;
                current_ctx.sched_info.saved_ctrls = 0;
                current_ctx
                    .set(VmcsField::PinBasedVmExecControl, saved, None)
                    .unwrap();
                vcpu.set_pin_based_ctrls(PinbasedControls::from_bits_truncate(saved as u32))
                    .unwrap();
            }
            next_ctx
                .copy_interrupt_frame(current_ctx, vcpu, false)
                .unwrap();
            // Set the return values.
            next_ctx
                .set(VmcsField::GuestRax, MONITOR_SWITCH_INTERRUPTED, None)
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
                .set(VmcsField::GuestRax, MONITOR_SUCCESS, None)
                .or(Err(CapaError::PlatformError))?;
            next_ctx
                .set(VmcsField::GuestRdi, return_capa.as_usize(), None)
                .or(Err(CapaError::PlatformError))?;
        }

        // Now the logic for shared vs. private vmcs.
        if current_ctx.vmcs == next_ctx.vmcs {
            panic!("Why are the two vmcs the same?");
        }

        //next_ctx.switch_flush(&RC_VMCS, vcpu);
        next_ctx.switch_no_flush(&RC_VMCS, vcpu);
        if delta != 0 {
            // We should do it differently, e.g., put it in the cache.
            // But the problem is that ctrls fields behave in an odd way (see vmx/src/lib.rs
            // set_ctrls).
            next_ctx.sched_info.timed = true;
            //TODO change this.
            next_ctx.sched_info.saved_ctrls = next_ctx
                .get_current(VmcsField::PinBasedVmExecControl, Some(vcpu))
                .unwrap();
            next_ctx.sched_info.budget = delta;
            let mut pin =
                PinbasedControls::from_bits_truncate(next_ctx.sched_info.saved_ctrls as u32);
            pin.set(PinbasedControls::VMX_PREEMPTION_TIMER, true);
            next_ctx
                .set(VmcsField::PinBasedVmExecControl, pin.bits() as usize, None)
                .unwrap();
            next_ctx
                .set(VmcsField::VmxPreemptionTimerValue, delta, None)
                .unwrap();
        }
        next_ctx.flush(vcpu);

        vcpu.set_ept_ptr(HostPhysAddr::new(
            next_domain.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
        ))
        .expect("Failed to update EPT");
        Ok(())
    }
}
