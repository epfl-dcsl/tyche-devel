//! Platform specific configuration

use core::arch::asm;
use core::sync::atomic::Ordering;

use capa_engine::context::RegisterGroup;
use capa_engine::utils::BitmapIterator;
use capa_engine::{
    permission, AccessRights, CapaEngine, CapaError, Domain, Handle, LocalCapa, MemOps,
};
use mmu::eptmapper::EPT_ROOT_FLAGS;
use mmu::FrameAllocator;
use spin::MutexGuard;
use stage_two_abi::{GuestInfo, Manifest};
use utils::HostPhysAddr;
use vmx::bitmaps::{exit_qualification, ExitControls, PinbasedControls, RFlags};
use vmx::fields::VmcsField;
use vmx::{VmxError, VmxExitReason};

use super::context::{ContextGpx86, Contextx86};
use super::cpuid_filter::{filter_mpk, filter_tpause};
use super::init::NB_BOOTED_CORES;
use super::perf::PerfEvent;
use super::state::{DataX86, StateX86, VmxState, CONTEXTS, DOMAINS, IOMMU, TLB_FLUSH};
use super::vmx_helper::{dump_host_state, load_host_state};
use super::{perf, vmx_helper};
use crate::allocator::{self, allocator};
use crate::calls::{MONITOR_FAILURE, MONITOR_SUCCESS};
use crate::monitor::{CoreUpdate, LogicalID, Monitor, PlatformState};
use crate::x86_64::context::CpuidEntry;
use crate::x86_64::state::TLB_FLUSH_BARRIERS;
use crate::{calls, MonitorErrors};

#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

//TODO(charly): see comment below.
//#[cfg(not(feature = "bare_metal"))]
pub fn remap_core(core: usize) -> usize {
    core
}

//TODO(charly) see comment below.
//#[cfg(not(feature = "bare_metal"))]
pub fn remap_core_bitmap(bitmap: u64) -> u64 {
    bitmap
}

//TODO(charly), TODO(aghosn) check if the new parsing of logical cores solves
//the issue on the EPFL machine and if we can remove these. For the moment,
//I comment them out.
/*#[cfg(feature = "bare_metal")]
pub fn remap_core(core: usize) -> usize {
    // Our harware has hyper-threads, and renames all co-located threads
    if core < 8 {
        core * 2
    } else {
        (core - 8) * 2 + 1
    }
}

#[cfg(feature = "bare_metal")]
pub fn remap_core_bitmap(bitmap: u64) -> u64 {
    let mut new_bitmap = 0;
    for idx in 0..16 {
        if bitmap & (1 << idx) != 0 {
            new_bitmap |= 1 << remap_core(idx);
        }
    }

    new_bitmap
}*/

impl PlatformState for StateX86 {
    type DomainData = DataX86;
    type Context = Contextx86;

    fn find_buff(
        engine: &MutexGuard<CapaEngine>,
        domain_handle: Handle<Domain>,
        addr: usize,
        end: usize,
    ) -> Option<usize> {
        let domain = Self::get_domain(domain_handle);
        let permission_iter = engine.get_domain_permissions(domain_handle).unwrap();
        for range in domain.remapper.remap(permission_iter) {
            let range_start = range.gpa;
            let range_end = range_start + range.size;
            if range_start <= addr
                && addr < range_end
                && range_start < end
                && end <= range_end
                && range.ops.contains(MemOps::WRITE)
            {
                // We found a valid region that encapsulate the buffer!
                // On x86_64 it is possible that we use some relocations, so compute the physical
                // address of the buffer.
                let gpa_to_hpa_offset = (range.gpa as isize) - (range.hpa as isize);
                let start = (addr as isize) - gpa_to_hpa_offset;
                return Some(start as usize);
            }
        }
        return None;
    }

    fn platform_init_io_mmu(&self, addr: usize) {
        let mut iommu = IOMMU.lock();
        iommu.set_addr(addr);
    }

    fn get_domain(domain: Handle<Domain>) -> MutexGuard<'static, Self::DomainData> {
        DOMAINS[domain.idx()].lock()
    }

    fn get_context(domain: Handle<Domain>, core: LogicalID) -> MutexGuard<'static, Self::Context> {
        CONTEXTS[domain.idx()][core.as_usize()].lock()
    }

    fn remap_core(core: usize) -> usize {
        return remap_core(core);
    }

    fn remap_core_bitmap(bitmap: u64) -> u64 {
        return remap_core_bitmap(bitmap);
    }

    fn max_cpus() -> usize {
        NB_BOOTED_CORES.load(core::sync::atomic::Ordering::SeqCst) + 1
    }

    fn create_context(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        current: Handle<Domain>,
        domain: Handle<Domain>,
        core: LogicalID,
    ) -> Result<(), CapaError> {
        let allocator = allocator();
        let dest = &mut Self::get_context(domain, core);
        // Reset all the values inside the dest.
        dest.reset();
        let frame = allocator.allocate_frame().unwrap();
        dest.vmcs = Some(frame);
        // Init the frame it needs the identifier.
        self.vmxon.init_frame(frame);
        // Init the host state.
        {
            let current_ctxt = Self::get_context(current, Self::logical_id());
            let mut values: [usize; 13] = [0; 13];
            dump_host_state(&mut self.vcpu, &mut values).or(Err(CapaError::InvalidValue))?;
            // Switch to the target frame.
            self.vcpu.switch_frame(dest.vmcs.unwrap()).unwrap();
            // Init to the default values.
            let info: GuestInfo = Default::default();
            vmx_helper::default_vmcs_config(&mut self.vcpu, &info, false);
            // If we need to trap ext_intr, we enable external interrupt exiting.
            if Self::should_trap_external_interrupt(engine, &domain) {
                self.vcpu
                    .set_pin_based_ctrls(
                        self.vcpu
                            .get_pin_based_ctrls()
                            .unwrap()
                            .union(PinbasedControls::EXTERNAL_INTERRUPT_EXITING),
                    )
                    .unwrap();
                /*Check if we can capture the interrupt number.*/
                if Self::should_ack_interrupt(engine, &domain) {
                    let exit_ctrl = self
                        .vcpu
                        .get_vm_exit_ctrls()
                        .unwrap()
                        .union(ExitControls::ACK_INTERRUPT_ON_EXIT);
                    self.vcpu.set_vm_exit_ctrls(exit_ctrl).unwrap();
                }
            }
            // Set the exception bitmap too.
            let exception = Self::translated_exception(engine, &domain);
            self.vcpu.set_exception_bitmap(exception).unwrap();

            let vpid = (domain.idx() + 1) as u16; // VPID 0 is reserved for VMX root execution
            self.vcpu.set_vpid(vpid).expect("Failled to install VPID");

            // Load the default values.
            load_host_state(&mut self.vcpu, &mut values).or(Err(CapaError::InvalidValue))?;
            self.vcpu.vmclear().expect("Could not clear vCPU");

            // Switch back the frame.
            self.vcpu.switch_frame(current_ctxt.vmcs.unwrap()).unwrap();
        }
        return Ok(());
    }

    fn update_permission(domain: Handle<Domain>, engine: &mut MutexGuard<CapaEngine>) -> bool {
        if engine[domain].is_io() {
            Self::update_domain_iopt(domain, engine)
        } else {
            Self::update_domain_ept(domain, engine)
        }
    }

    fn create_domain(domain: Handle<Domain>) {
        let mut domain = Self::get_domain(domain);
        let allocator = allocator();
        if let Some(ept) = domain.ept {
            unsafe { Self::free_ept(ept, allocator) }
        }
        let ept_root = allocator
            .allocate_frame()
            .expect("Failed to allocate EPT root")
            .zeroed();
        domain.ept = Some(ept_root.phys_addr);
    }

    fn revoke_domain(domain: Handle<Domain>) {
        let ctxt = Self::get_context(domain, Self::logical_id());
        if ctxt.launched {
            vmx::ActiveVmcs::vmclear_cached(&ctxt.vmcs.unwrap()).unwrap();
        }
    }

    fn apply_core_update(
        &mut self,
        current_domain: &mut Handle<Domain>,
        core: LogicalID,
        update: &CoreUpdate,
    ) {
        let vcpu = &mut self.vcpu;
        log::trace!("Core Update: {} on core {}", update, core);
        match update {
            CoreUpdate::TlbShootdown { src_core: _ } => {
                // Into a separate function so that we can drop the domain lock before starting to
                // wait on the TLB_FLUSH_BARRIER
                self.platform_shootdown(current_domain, core, false);
                log::trace!("core {} waits on tlb flush barrier", core);
                TLB_FLUSH_BARRIERS[current_domain.idx()].wait();
                log::trace!("core {} done waiting", core);
            }
            CoreUpdate::Switch {
                domain,
                return_capa,
                delta,
            } => {
                log::trace!("Domain Switch on core {} with delta {}", core, delta);

                let mut current_ctx = Self::get_context(*current_domain, core);
                let mut next_ctx = Self::get_context(*domain, core);
                let next_domain = Self::get_domain(*domain);
                Self::switch_domain(
                    vcpu,
                    &mut current_ctx,
                    &mut next_ctx,
                    next_domain,
                    *return_capa,
                    *delta,
                )
                .expect("Failed to perform the switch");
                // Update the current domain and context handle
                *current_domain = *domain;
            }
            CoreUpdate::Trap {
                manager: _manager,
                trap,
                info: _info,
            } => {
                log::trace!("Trap {} on core {}", trap, core);
                log::debug!(
                    "Exception Bitmap is {:b}",
                    vcpu.get_exception_bitmap().expect("Failed to read bitmpap")
                );
                todo!("Update this code path.");
            }
            CoreUpdate::DomainRevocation { revok, next } => {
                Self::revoke_domain(*revok);
                // If we're running the domain revoked, we need to perform a switch.
                if revok.idx() == current_domain.idx() {
                    // Mark ourselves as interrupted.
                    let mut curr_ctx = Self::get_context(*current_domain, core);
                    curr_ctx.interrupted = true;
                    let mut next_ctx = Self::get_context(*next, core);
                    let next_dom = Self::get_domain(*next);
                    Self::switch_domain(vcpu, &mut curr_ctx, &mut next_ctx, next_dom, None, 0)
                        .expect("Unable to perform the switch");
                    // Notify that we preemted the domain.
                    // This has to be done after the switch to override the exit
                    // reason.
                    next_ctx.set(VmcsField::GuestRax, 1, None).unwrap();
                    next_ctx
                        .set(
                            VmcsField::GuestR8,
                            MonitorErrors::DomainRevoked as usize,
                            None,
                        )
                        .unwrap();
                    // Don't forget to swith the current domain.
                    *current_domain = *next;
                }
                TLB_FLUSH_BARRIERS[revok.idx()].wait();
                // Wait for the main thread to finish updating the engine.
                TLB_FLUSH_BARRIERS[next.idx()].wait();
            }
        }
    }

    fn platform_shootdown(&mut self, domain: &Handle<Domain>, core: LogicalID, trigger: bool) {
        let dom = Self::get_domain(*domain);
        let new_epts = dom.ept.unwrap().as_usize() | EPT_ROOT_FLAGS;
        let mut context = Self::get_context(*domain, core);
        // We triggered the update.
        if trigger {
            context.set(VmcsField::EptPointer, new_epts, None).unwrap();
        } else {
            context
                .set(VmcsField::EptPointer, new_epts, Some(&mut self.vcpu))
                .unwrap();
        }
    }

    fn set_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: LogicalID,
        idx: usize,
        value: usize,
    ) -> Result<(), CapaError> {
        let mut ctxt = Self::get_context(*domain, core);
        let field = VmcsField::from_u32(idx as u32).ok_or(CapaError::InvalidValue)?;
        let (group, idx) = Contextx86::translate_field(field);
        // Check the permissions.
        let (_, perm_write) = group.to_permissions();
        let bitmap = engine.get_domain_permission(*domain, perm_write);
        // Not allowed.
        if engine.is_domain_sealed(*domain) && ((1 << idx) & bitmap == 0) {
            return Err(CapaError::InsufficientPermissions);
        }
        // Special cases: Exception bitmap and external interrupts.
        // As these relate to domain configuration, we need to take extra care when
        // setting the fields.
        match field {
            VmcsField::ExceptionBitmap => {
                if value as u32 != Self::translated_exception(engine, domain).bits() {
                    return Err(CapaError::AlreadyFrozen);
                }
            }
            VmcsField::PinBasedVmExecControl => {
                let should_trap = StateX86::should_trap_external_interrupt(engine, domain);
                let traps =
                    (value & PinbasedControls::EXTERNAL_INTERRUPT_EXITING.bits() as usize) != 0;
                if traps != should_trap {
                    log::error!(
                        "Attempt to change external interrupt traps from {} to {}",
                        should_trap,
                        traps
                    );
                    return Err(CapaError::AlreadyFrozen);
                }
            }
            _ => { /*Nothing to do*/ }
        }

        ctxt.set(field, value, None)
            .or(Err(CapaError::PlatformError))
    }

    fn get_core(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: LogicalID,
        idx: usize,
    ) -> Result<usize, CapaError> {
        let mut ctxt = Self::get_context(*domain, core);
        let field = VmcsField::from_u32(idx as u32).ok_or(CapaError::InvalidValue)?;
        let (group, idx) = Contextx86::translate_field(field);
        // Check the permissions.
        let (perm_read, _) = group.to_permissions();
        let bitmap = engine.get_domain_permission(*domain, perm_read);
        // Not allowed.
        if engine.is_domain_sealed(*domain) && ((1 << idx) & bitmap == 0) {
            return Err(CapaError::InsufficientPermissions);
        }
        //TODO: patch.
        //let rcvmcs = RC_VMCS.lock();
        //let frame = rcvmcs.get(ctxt.vmcs).unwrap();
        let restore = *self.vcpu.frame();
        self.vcpu.switch_frame(ctxt.vmcs.unwrap()).unwrap();
        let res = ctxt
            .get_from_frame(field, &self.vcpu)
            .or(Err(CapaError::PlatformError));
        self.vcpu.switch_frame(restore).unwrap();
        return res;
    }

    fn get_core_gp(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: LogicalID,
        result: &mut [usize],
    ) -> Result<(), CapaError> {
        let ctxt = Self::get_context(*domain, core);
        let (perm_read, _) = RegisterGroup::RegGp.to_permissions();
        let bitmap = engine.get_domain_permission(*domain, perm_read);
        let is_sealed = engine.is_domain_sealed(*domain);
        for idx in 0..(ContextGpx86::size() - 1) {
            if is_sealed && ((1 << idx) & bitmap == 0) {
                return Err(CapaError::InsufficientPermissions);
            }
            result[idx] = ctxt.regs.state_gp.values[idx];
        }
        Ok(())
    }

    fn dump_in_gp(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: &mut Handle<Domain>,
        core: LogicalID,
        src: &[usize],
    ) -> Result<(), CapaError> {
        let mut ctxt = Self::get_context(*domain, core);
        ctxt.regs.state_gp.values[0..ContextGpx86::size() - 1].copy_from_slice(src);
        Ok(())
    }

    fn extract_from_gp(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: &Handle<Domain>,
        core: LogicalID,
        res: &mut [(usize, usize); 6],
    ) -> Result<(), CapaError> {
        let mut ctxt = Self::get_context(*domain, core);
        res[0] = (
            ctxt.get_current(VmcsField::GuestRbp, None).unwrap(),
            ctxt.get_current(VmcsField::GuestRbx, None).unwrap(),
        );
        res[1] = (
            ctxt.get_current(VmcsField::GuestRcx, None).unwrap(),
            ctxt.get_current(VmcsField::GuestRdx, None).unwrap(),
        );
        res[2] = (
            ctxt.get_current(VmcsField::GuestR8, None).unwrap(),
            ctxt.get_current(VmcsField::GuestR9, None).unwrap(),
        );
        res[3] = (
            ctxt.get_current(VmcsField::GuestR10, None).unwrap(),
            ctxt.get_current(VmcsField::GuestR11, None).unwrap(),
        );
        res[4] = (
            ctxt.get_current(VmcsField::GuestR12, None).unwrap(),
            ctxt.get_current(VmcsField::GuestR13, None).unwrap(),
        );
        res[5] = (
            ctxt.get_current(VmcsField::GuestR14, None).unwrap(),
            ctxt.get_current(VmcsField::GuestR15, None).unwrap(),
        );
        Ok(())
    }

    fn check_overlaps(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> bool {
        let dom_dat = Self::get_domain(domain);
        dom_dat
            .remapper
            .overlaps(alias, repeat * (region.end - region.start))
    }

    fn map_region(
        &mut self,
        engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        repeat: usize,
        region: &AccessRights,
    ) -> Result<(), CapaError> {
        let mut dom_dat = Self::get_domain(domain);
        let _ = dom_dat
            .remapper
            .map_range(region.start, alias, region.end - region.start, repeat)
            .unwrap(); // Overlap is checked again but should not be triggered.
        engine.conditional_permission_update(domain);
        Ok(())
    }

    fn unmap_region(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        alias: usize,
        size: usize,
    ) -> Result<(), CapaError> {
        let mut data = Self::get_domain(domain);
        let _ = data.remapper.unmap_gpa_range(alias, size).unwrap();
        Ok(())
    }

    fn prepare_notify(domain: &Handle<Domain>, core_count: usize) {
        TLB_FLUSH_BARRIERS[domain.idx()].set_count(core_count);
    }

    fn notify_cores(_domain: &Handle<Domain>, core_id: LogicalID, core_map: usize) {
        for core in BitmapIterator::new(core_map as u64).map(|x| LogicalID(x)) {
            if core == core_id {
                continue;
            }
            x2apic::send_init_assert(core.physical().as_u32());
        }
    }

    fn acknowledge_notify(domain: &Handle<Domain>) {
        TLB_FLUSH_BARRIERS[domain.idx()].wait();
    }

    fn finish_notify(domain: &Handle<Domain>) {
        let mut dom = Self::get_domain(*domain);
        let allocator = allocator();
        if let Some(ept) = dom.ept_old {
            unsafe { Self::free_ept(ept, allocator) };
        }
        dom.ept_old = None;
        TLB_FLUSH[domain.idx()].store(false, Ordering::SeqCst);
    }

    fn context_interrupted(&mut self, domain: &Handle<Domain>, core: LogicalID) {
        let mut context = Self::get_context(*domain, core);
        context.interrupted = true;
    }

    fn find_hpa(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        domain: Handle<Domain>,
        gpa: usize,
        size: usize,
    ) -> Result<(usize, usize), CapaError> {
        let dom = Self::get_domain(domain);
        for seg in dom.remapper.iter_segments() {
            let seg_size = seg.size * seg.repeat;
            // Okay we found the segment.
            if seg.gpa <= gpa && (seg.gpa + seg_size) > gpa {
                let hpa = if seg.repeat == 1 {
                    seg.hpa + (gpa - seg.gpa)
                } else {
                    seg.hpa + ((seg.gpa - gpa) % seg.size)
                };
                let res_size = if seg.size >= size { size } else { seg.size };
                return Ok((hpa, res_size));
            }
        }
        // Not found, we assume the result is Identity mapped.
        Ok((gpa, size))
    }

    fn inject_interrupt(
        &mut self,
        _engine: &mut MutexGuard<CapaEngine>,
        _domain: &Handle<Domain>,
        trapnr: u8,
    ) -> Result<(), CapaError> {
        let interrupt = self.vcpu.interrupt_info().unwrap();
        if interrupt.is_none()
            || !interrupt.unwrap().valid()
            || interrupt.unwrap().vector() != trapnr
        {
            log::error!("Invalid interrupt in the injection.");
            return Err(CapaError::InvalidOperation);
        }
        // Check if interrupts are blocked.
        if self.vcpu.get(VmcsField::GuestRflags).unwrap() & RFlags::INTERRUPT_FLAG.bits() as usize
            == 0
        {
            //TODO: decide what we do in this case.
            return Ok(());
        }
        self.vcpu
            .inject_interrupt(interrupt.unwrap())
            .map_err(|_| CapaError::PlatformError)?;
        return Ok(());
    }
}

// ————————————————————— Monitor Implementation on X86 —————————————————————— //

pub struct MonitorX86 {}

impl Monitor<StateX86> for MonitorX86 {}

impl MonitorX86 {
    pub fn init(manifest: &'static Manifest, bsp: bool) -> (StateX86, Handle<Domain>) {
        let allocator = allocator::allocator();
        let vmxon_frame = allocator
            .allocate_frame()
            .expect("Failed to allocate VMXON frame")
            .zeroed();
        let vmxon = unsafe { vmx::vmxon(vmxon_frame).expect("Failed to execute VMXON") };
        let vmcs_frame = allocator
            .allocate_frame()
            .expect("Failed to allocate VMCS frame")
            .zeroed();
        let vmcs = unsafe {
            vmxon
                .create_vm_unsafe(vmcs_frame)
                .expect("Failed to create VMCS")
        };
        let vcpu = vmcs.set_as_active().expect("Failed to set VMCS as active");
        let mut state = VmxState { vcpu, vmxon };
        let domain = if bsp {
            Self::do_init(&mut state, manifest)
        } else {
            Self::start_initial_domain(&mut state)
        };
        let dom = StateX86::get_domain(domain);
        let mut ctx = StateX86::get_context(domain, StateX86::logical_id());
        ctx.vmcs = Some(*state.vcpu.frame());
        state
            .vcpu
            .set_ept_ptr(HostPhysAddr::new(
                dom.ept.unwrap().as_usize() | EPT_ROOT_FLAGS,
            ))
            .expect("Failed to set initial EPT ptr");
        unsafe {
            vmx_helper::init_vcpu(&mut state.vcpu, &manifest.info, &mut ctx);
        }
        state
            .vcpu
            .set_vpid((domain.idx() + 1) as u16)
            .expect("Failed to set VPID");
        (state, domain)
    }

    pub fn launch_guest(
        &mut self,
        manifest: &'static Manifest,
        state: StateX86,
        domain: Handle<Domain>,
    ) {
        if !manifest.info.loaded {
            log::warn!("No guest found, exiting");
            return;
        }
        log::info!("Staring main loop");
        self.main_loop(state, domain);
        qemu::exit(qemu::ExitCode::Success);
    }

    pub fn emulate_cpuid(domain: &mut Handle<Domain>) {
        let mut context = StateX86::get_context(*domain, StateX86::logical_id());
        let input_eax = context.get_current(VmcsField::GuestRax, None).unwrap();
        let input_ecx = context.get_current(VmcsField::GuestRcx, None).unwrap();
        let mut eax: usize;
        let mut ebx: usize;
        let mut ecx: usize;
        let mut edx: usize;

        unsafe {
            // Note: LLVM reserves %rbx for its internal use, so we need to use a scratch
            // register for %rbx here.
            asm!(
                "mov {tmp}, rbx",
                "cpuid",
                "mov rsi, rbx",
                "mov rbx, {tmp}",
                tmp = out(reg) _,
                inout("rax") input_eax => eax,
                inout("rcx") input_ecx => ecx,
                out("rdx") edx,
                out("rsi") ebx
            )
        }

        //Apply cpuid filters.
        filter_tpause(input_eax, input_ecx, &mut eax, &mut ebx, &mut ecx, &mut edx);
        filter_mpk(input_eax, input_ecx, &mut eax, &mut ebx, &mut ecx, &mut edx);

        context
            .set(VmcsField::GuestRax, eax as usize, None)
            .unwrap();
        context
            .set(VmcsField::GuestRbx, ebx as usize, None)
            .unwrap();
        context
            .set(VmcsField::GuestRcx, ecx as usize, None)
            .unwrap();
        context
            .set(VmcsField::GuestRdx, edx as usize, None)
            .unwrap();
    }

    fn emulate_cpuid_cached(&self, domain: Handle<Domain>) -> Result<(), ()> {
        let mut context = StateX86::get_context(domain, StateX86::logical_id());

        if context.nb_active_cpuid_entries == 0 {
            // No cached cpuid
            return Err(());
        }

        let function = context.get_current(VmcsField::GuestRax, None).unwrap() as u32;
        let index = context.get_current(VmcsField::GuestRcx, None).unwrap() as u32;

        for i in 0..context.nb_active_cpuid_entries {
            let entry = &context.cpuid_entries[i];

            if entry.function != function {
                // Function does not match, check the next one
                continue;
            }

            // If the  index is not significant, or if the index is the same
            if (entry.flags & 0b1 == 0) || entry.index == index {
                let eax = entry.eax;
                let ebx = entry.ebx;
                let ecx = entry.ecx;
                let edx = entry.edx;
                // log::trace!(
                //     "Successful CPUID emulation: {:08x} {:08x} - {:08x} {:08x} {:08x} {:08x}",
                //     function,
                //     index,
                //     eax,
                //     ebx,
                //     ecx,
                //     edx
                // );
                // return Err(());
                context
                    .set(VmcsField::GuestRax, eax as usize, None)
                    .unwrap();
                context
                    .set(VmcsField::GuestRbx, ebx as usize, None)
                    .unwrap();
                context
                    .set(VmcsField::GuestRcx, ecx as usize, None)
                    .unwrap();
                context
                    .set(VmcsField::GuestRdx, edx as usize, None)
                    .unwrap();
                return Ok(());
            }
        }

        // log::trace!("Failed to emulate CPUID: {:08x} {:08x}", function, index);
        Err(())
    }

    pub unsafe fn run_vcpu(
        &mut self,
        state: &mut StateX86,
        context: &mut Contextx86,
    ) -> Result<VmxExitReason, VmxError> {
        if !context.launched {
            context.launched = true;
            state.vcpu.launch(&mut context.regs.state_gp.values)
        } else {
            state.vcpu.resume(&mut context.regs.state_gp.values)
        }
    }

    pub fn main_loop(&mut self, mut state: StateX86, mut domain: Handle<Domain>) {
        let core_id = StateX86::logical_id();
        let mut result = unsafe {
            let mut context = StateX86::get_context(domain, core_id);
            self.run_vcpu(&mut state, &mut context)
        };
        loop {
            perf::start();
            let exit_reason = match result {
                Ok(exit_reason) => {
                    let res = self
                        .handle_exit(&mut state, exit_reason, &mut domain)
                        .expect("Failed to handle VM exit");

                    // Apply core-local updates before returning
                    Self::apply_core_updates(&mut state, &mut domain);

                    res
                }
                Err(err) => {
                    log::error!(
                        "Guest crash: {:?} | dom{} | core {}",
                        err,
                        domain.idx(),
                        StateX86::logical_id()
                    );
                    log::error!("Vcpu: {:x?}", state.vcpu);
                    HandlerResult::Crash
                }
            };

            match exit_reason {
                HandlerResult::Resume => {
                    perf::commit();
                    perf::display_stats();
                    result = unsafe {
                        let mut context = StateX86::get_context(domain, core_id);
                        context.flush(&mut state.vcpu);
                        self.run_vcpu(&mut state, &mut context)
                    };
                }
                _ => {
                    log::info!("Exiting guest: {:?}", exit_reason);
                    break;
                }
            }
        }
    }

    pub fn handle_exit(
        &mut self,
        vs: &mut StateX86,
        reason: VmxExitReason,
        domain: &mut Handle<Domain>,
    ) -> Result<HandlerResult, CapaError> {
        match reason {
            VmxExitReason::Vmcall => {
                let (vmcall, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6) = {
                    let mut context = StateX86::get_context(*domain, StateX86::logical_id());
                    let vmcall = context.get_current(VmcsField::GuestRax, None).unwrap();
                    let arg_1 = context.get_current(VmcsField::GuestRdi, None).unwrap();
                    let arg_2 = context.get_current(VmcsField::GuestRsi, None).unwrap();
                    let arg_3 = context.get_current(VmcsField::GuestRdx, None).unwrap();
                    let arg_4 = context.get_current(VmcsField::GuestRcx, None).unwrap();
                    let arg_5 = context.get_current(VmcsField::GuestR8, None).unwrap();
                    let arg_6 = context.get_current(VmcsField::GuestR9, None).unwrap();
                    (vmcall, arg_1, arg_2, arg_3, arg_4, arg_5, arg_6)
                };
                let args: [usize; 6] = [arg_1, arg_2, arg_3, arg_4, arg_5, arg_6];
                let mut res: [usize; 6] = [0; 6];

                // Track the VMCall events
                match vmcall {
                    calls::SWITCH => perf::event(PerfEvent::VmcallSwitch),
                    calls::DUPLICATE => perf::event(PerfEvent::VmcallDuplicate),
                    calls::ENUMERATE => perf::event(PerfEvent::VmcallEnumerate),
                    calls::READ_ALL_GP => perf::event(PerfEvent::VmcallGetAllGp),
                    calls::WRITE_ALL_GP => perf::event(PerfEvent::VmcallWriteAllGp),
                    calls::WRITE_FIELDS=> perf::event(PerfEvent::VmcallWriteField),
                    calls::CONFIGURE => perf::event(PerfEvent::VmcallConfigure),
                    calls::CONFIGURE_CORE => perf::event(PerfEvent::VmcallConfigureCore),
                    calls::GET_CONFIG_CORE => perf::event(PerfEvent::VmcallGetConfigCore),
                    calls::SELF_CONFIG => perf::event(PerfEvent::VmcallSelfConfigure),
                    calls::RETURN_TO_MANAGER => perf::event(PerfEvent::VmcallReturnToManager),
                    calls::GET_HPA => perf::event(PerfEvent::VmcallGetHpa),
                    _ => perf::event(PerfEvent::Vmcall)
                }

                // Special case for switch.
                if vmcall == calls::SWITCH {
                    vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
                } else if vmcall == calls::EXIT {
                    return Ok(HandlerResult::Exit);
                }

                let success  = match vmcall {
                    calls::EXIT => return Ok(HandlerResult::Exit),
                    calls::SET_CPUID_ENTRY => {
                        let engine = Self::lock_engine(vs, domain);
                        let target = engine.get_domain_capa(*domain, LocalCapa::new(args[0])).expect("Invalid capa for SET_CPUID_ENTRY");
                        self.install_cpuid_entry(target, &args)
                    }
                    _ => Self::do_monitor_call(vs, domain, vmcall, &args, &mut res)
                };
                // Put the results back.
                let mut context = StateX86::get_context(*domain, StateX86::logical_id());
                match success {
                    Ok(true) => {
                          context.set(VmcsField::GuestRax, MONITOR_SUCCESS, None).unwrap();
                          context.set(VmcsField::GuestRdi, res[0], None).unwrap();
                          context.set(VmcsField::GuestRsi, res[1], None).unwrap();
                          context.set(VmcsField::GuestRdx, res[2], None).unwrap();
                          context.set(VmcsField::GuestRcx, res[3], None).unwrap();
                          context.set(VmcsField::GuestR8, res[4], None).unwrap();
                          context.set(VmcsField::GuestR9, res[5], None).unwrap();
                    },
                    Ok(false) => {},
                    Err(e) => {
                        if vmcall != calls::SET_CPUID_ENTRY {
                        log::error!("Failure monitor call: {:?}, call: {:?} for dom {} on core {}", e, vmcall, domain.idx(), StateX86::logical_id());
                        context.set(VmcsField::GuestRax, MONITOR_FAILURE, None).unwrap();
                        log::debug!("The vcpu: {:#x?}", vs.vcpu);
                        drop(context);
                        let callback = |dom: Handle<Domain>, engine: &mut CapaEngine| {
                            let dom_dat = StateX86::get_domain(dom);
                            log::debug!("remaps {}", dom_dat.remapper.iter_segments());
                            let remap = dom_dat.remapper.remap(engine.get_domain_permissions(dom).unwrap());
                            log::debug!("remapped: {}", remap);
                        };
                        Self::do_debug(vs, domain, callback);
                        }
                    }
                }
                if vmcall != calls::SWITCH {
                    vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
                }
                Ok(HandlerResult::Resume)
            }
        VmxExitReason::InitSignal /*if domain.idx() == 0*/ => {
            log::trace!("cpu {} received init signal", StateX86::logical_id());
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Cpuid => {
            perf::event(PerfEvent::Cpuid);

            // Domain 0 gets direct access to CPUID
            if domain.idx() == 0 {
                Self::emulate_cpuid(domain);
                vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
                return Ok(HandlerResult::Resume)
            }
            // Otherwise check if we have cached CPUID entries
            match self.emulate_cpuid_cached(*domain) {
                // Successfully emulated CPUID
                Ok(_) => {
                    vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
                    return Ok(HandlerResult::Resume);
                }
                // Failed to emulate CPUID, continuing
                Err(_) => (),
            }
            // Finaly some domains get direct access to CPUID
            let perms = Self::do_get_self(vs, domain, permission::PermissionIndex::MonitorInterface)?;
            if perms & permission::monitor_inter_perm::CPUID as usize != 0 {
                Self::emulate_cpuid(domain);
                vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
                return Ok(HandlerResult::Resume);
            }
            match Self::do_switch_to_manager(vs, domain) {
                Ok(_) => {
                    return Ok(HandlerResult::Resume);
                }
                Err(e) => {
                    log::error!("Unable to handle cpuid: {:?}", e);
                    log::info!("The vcpu: {:x?}", vs.vcpu);
                    return Ok(HandlerResult::Crash);
                }
            }
        }
        VmxExitReason::ControlRegisterAccesses if domain.idx() == 0 => {
            perf::event(PerfEvent::ControlRegisterAccess);
            // Handle some of these only for dom0, the other domain's problems
            // are for now forwarded to the manager domain.
            let mut context = StateX86::get_context(*domain, StateX86::logical_id());
            let qualification = vs.vcpu.exit_qualification().or(Err(CapaError::PlatformError))?.control_register_accesses();
            match qualification {
                exit_qualification::ControlRegisterAccesses::MovToCr(cr, reg) => {
                    log::info!("MovToCr {:?} into {:?} on domain {:?}", reg, cr, *domain);
                    if !cr.is_guest_cr() {
                        log::error!("Invalid register: {:x?}", cr);
                        panic!("VmExit reason for access to control register is not a control register.");
                    }
                    if cr == VmcsField::GuestCr4 {
                        let value = context.get_current(reg, Some(&mut vs.vcpu)).or(Err(CapaError::PlatformError))? as usize;
                        context.set(VmcsField::Cr4ReadShadow, value, Some(&mut vs.vcpu)).or(Err(CapaError::PlatformError))?;
                        let real_value = value | (1 << 13); // VMXE
                        context.set(cr, real_value, Some(&mut vs.vcpu)).or(Err(CapaError::PlatformError))?;
                    } else {
                        todo!("Handle cr: {:?}", cr);
                    }

                    vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
                }
                _ => todo!("Emulation not yet implemented for {:?}", qualification),
            };
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::EptViolation if domain.idx() == 0 => {
            perf::event(PerfEvent::EptViolation);
            let addr = vs.vcpu.guest_phys_addr().or(Err(CapaError::PlatformError))?;
            log::error!(
                "EPT Violation on dom0 core {}! virt: 0x{:x}, phys: 0x{:x}",
                StateX86::logical_id(),
                vs.vcpu
                    .guest_linear_addr()
                    .expect("unable to get the virt addr")
                    .as_u64(),
                addr.as_u64(),
            );
            panic!("The vcpu {:x?}", vs.vcpu);
        }
        VmxExitReason::Exception if domain.idx() == 0 => {
            panic!("Received an exception on dom0?");
        }
        VmxExitReason::Xsetbv if domain.idx() == 0 => {
            perf::event(PerfEvent::Xsetbv);
            let mut context = StateX86::get_context(*domain, StateX86::logical_id());
            let ecx = context.get_current(VmcsField::GuestRcx, None).or(Err(CapaError::PlatformError))?;
            let eax = context.get_current(VmcsField::GuestRax, None).or(Err(CapaError::PlatformError))?;
            let edx = context.get_current(VmcsField::GuestRdx, None).or(Err(CapaError::PlatformError))?;

            let xrc_id = ecx & 0xFFFFFFFF; // Ignore 32 high-order bits
            if xrc_id != 0 {
                log::error!("Xsetbv: invalid rcx 0x{:x}", ecx);
                return Ok(HandlerResult::Crash);
            }

            unsafe {
                asm!(
                    "xsetbv",
                    in("ecx") ecx,
                    in("eax") eax,
                    in("edx") edx,
                );
            }

            vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
            Ok(HandlerResult::Resume)
        }
        VmxExitReason::Wrmsr if domain.idx() == 0 => {
            perf::event(PerfEvent::Msr);
            let mut context = StateX86::get_context(*domain, StateX86::logical_id());
            let ecx = context.get_current(VmcsField::GuestRcx, None).or(Err(CapaError::PlatformError))?;
            if ecx >= 0x4B564D00 && ecx <= 0x4B564DFF {
                // Custom MSR range, used by KVM
                // See https://docs.kernel.org/virt/kvm/x86/msr.html
                // TODO: just ignore them for now, should add support in the future
                vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
                Ok(HandlerResult::Resume)
            } else {
                log::error!("Unknown MSR: 0x{:x}", ecx);
                Ok(HandlerResult::Crash)
            }
        }
        VmxExitReason::Rdmsr if domain.idx() == 0 => {
            perf::event(PerfEvent::Msr);
            let mut context = StateX86::get_context(*domain, StateX86::logical_id());
            let ecx = context.get_current(VmcsField::GuestRcx, None).or(Err(CapaError::PlatformError))?;
            log::trace!("rdmsr 0x{:x}", ecx);
            if ecx >= 0xc0010000 && ecx <= 0xc0020000 {
                // Reading an AMD specific register, just ignore it
                // The other interval seems to be related to pmu...
                // TODO: figure this out and why it only works on certain hardware.
                vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
                log::trace!("rdmsr ignoring amd registers");
                Ok(HandlerResult::Resume)
            } else {
                let msr_reg = vmx::msr::Msr::new(ecx as u32);
                log::trace!("rdmsr: about to read");
                let (low, high) = unsafe { msr_reg.read_raw() };
                log::trace!("Emulated read of msr {:x} = h:{:x};l:{:x}", ecx, high, low);
                context.set(VmcsField::GuestRax, low as usize, None).or(Err(CapaError::PlatformError))?;
                context.set(VmcsField::GuestRdx, high as usize, None).or(Err(CapaError::PlatformError))?;
                vs.vcpu.next_instruction().or(Err(CapaError::PlatformError))?;
                Ok(HandlerResult::Resume)
            }
        }
        // Routing exits to the manager domains.
        VmxExitReason::EptViolation
        | VmxExitReason::ExternalInterrupt
        | VmxExitReason::IoInstruction
        | VmxExitReason::ControlRegisterAccesses
        | VmxExitReason::TripleFault
        | VmxExitReason::Exception
        | VmxExitReason::Wrmsr
        | VmxExitReason::Rdmsr
        | VmxExitReason::Xsetbv
        | VmxExitReason::ApicWrite
        | VmxExitReason::InterruptWindow
        | VmxExitReason::Wbinvd
        | VmxExitReason::MovDR
        | VmxExitReason::VirtualizedEoi
        | VmxExitReason::ApicAccess
        | VmxExitReason::VmxPreemptionTimerExpired
        | VmxExitReason::AccessToGdtrOrIdtr
        | VmxExitReason::AccessToLdtrOrTr
        | VmxExitReason::Hlt => {
            log::trace!("Handling {:?} for dom {} on core {}", reason, domain.idx(), StateX86::logical_id());
            match reason {
                VmxExitReason::EptViolation => perf::event(PerfEvent::EptViolation),
                VmxExitReason::VmxPreemptionTimerExpired => perf::event(PerfEvent::VmxTimer),
                VmxExitReason::ControlRegisterAccesses => perf::event(PerfEvent::ControlRegisterAccess),
                VmxExitReason::Exception => perf::event(PerfEvent::Exception),
                VmxExitReason::IoInstruction => perf::event(PerfEvent::IoInstr),
                VmxExitReason::ExternalInterrupt => perf::event(PerfEvent::ExternalInt),
                VmxExitReason::Xsetbv => perf::event(PerfEvent::Xsetbv),
                VmxExitReason::VirtualizedEoi => perf::event(PerfEvent::VirtEoi),
                VmxExitReason::ApicAccess | VmxExitReason::ApicWrite => perf::event(PerfEvent::ApicAccess),
                VmxExitReason::Rdmsr | VmxExitReason::Wrmsr => perf::event(PerfEvent::Msr),
                _ => (),
            }

           /*if reason == VmxExitReason::EptViolation {
                log::info!("Ept violation for dom{} at {:x}", domain.idx(), vs.vcpu.get(VmcsField::GuestRip).unwrap());
                log::info!("Faulty address {:#x?}", vs.vcpu.guest_phys_addr().unwrap());
                let ept_root = StateX86::get_domain(*domain).ept.unwrap();
                let mut mapper = EptMapper::new(allocator().get_physical_offset().as_usize(), ept_root);
                mapper.debug_range(vs.vcpu.guest_phys_addr().unwrap(), 4096);
                log::info!("vs state: {:#x?}", vs.vcpu);
            }*/

            if reason == VmxExitReason::ExternalInterrupt {
                /*let address_eoi = 0xfee000b0 as *mut u32;
                unsafe {
                    // Clear the eoi
                    *address_eoi = 0;
                }*/

                /*let apic_base = unsafe { rdmsr(IA32_APIC_BASE) };
                if apic_base & (1 << 10) == 0 || apic_base & (1 << 11) == 0{
                    panic!("Uh oh {:b}", apic_base);
                }
                if (cpuid().as_usize() == 0 && apic_base != 0xfee00d00) || (cpuid().as_usize() != 0 && apic_base != 0xfee00c00) {
                    panic!("New value? {:#x}", apic_base);
                }*/
                x2apic::send_eoi();
            }
            // Route the interrupt.
            // TODO: we might need to ack interrupt to check the value.
            if reason == VmxExitReason::ExternalInterrupt {
                match vs.vcpu.interrupt_info().unwrap() {
                    Some(exit) if exit.valid() => {
                        match Self::do_route_interrupt(vs, domain, exit.vector()) {
                            Ok(_) => {
                                return Ok(HandlerResult::Resume);
                            }
                            Err(e) =>  {
                                log::error!("Unable to handle {:?}, {:?} trapnr {}",
                                    reason, e, exit.vector());
                                return Ok(HandlerResult::Crash);
                            }
                        }
                    }
                    _ => {/*Nothing to do*/}
                }
            }
            match Self::do_switch_to_manager(vs, domain) {
                Ok(_) => {
                    return Ok(HandlerResult::Resume);
                }
                Err(e) => {
                    log::error!("Unable to handle {:?}: {:?}", reason, e);
                    log::info!("The vcpu: {:x?}", vs.vcpu);
                    return Ok(HandlerResult::Crash);
                }
            }
        }
        _ => {
            log::error!(
                "Emulation is not yet implemented for exit reason: {:?}",
                reason
            );
            log::info!("Dom: {} on core {}\n{:?}", domain.idx(), StateX86::logical_id(), vs.vcpu);
            Ok(HandlerResult::Crash)
        }
        }
    }

    fn install_cpuid_entry(
        &mut self,
        domain: Handle<Domain>,
        args: &[usize; 6],
    ) -> Result<bool, CapaError> {
        let mut context = StateX86::get_context(domain, StateX86::logical_id());
        if context.nb_active_cpuid_entries >= context.cpuid_entries.len() {
            return Err(CapaError::OutOfMemory);
        }

        let function = args[1] as u32;
        let index = (args[2] & 0xffffffff) as u32;
        let flags = (args[2] >> 32) as u32;
        let eax = (args[3] & 0xffffffff) as u32;
        let ebx = (args[3] >> 32) as u32;
        let ecx = (args[4] & 0xffffffff) as u32;
        let edx = (args[4] >> 32) as u32;

        log::trace!(
            "Configure CPUID on domain {} {:08x} {:08x} {:08x} - {:08x} {:08x} {:08x} {:08x}",
            domain.idx(),
            function,
            index,
            flags,
            eax,
            ebx,
            ecx,
            edx
        );

        // Update permissions if already present
        for i in 0..context.nb_active_cpuid_entries {
            let entry = &mut context.cpuid_entries[i];
            if entry.function == function && entry.index == index {
                entry.flags = flags;
                entry.eax = eax;
                entry.ebx = ebx;
                entry.ecx = ecx;
                entry.edx = edx;

                return Ok(true);
            }
        }

        let idx = context.nb_active_cpuid_entries;
        context.nb_active_cpuid_entries += 1;
        context.cpuid_entries[idx] = CpuidEntry {
            function,
            index,
            flags,
            eax,
            ebx,
            ecx,
            edx,
        };

        return Ok(true);
    }
}
