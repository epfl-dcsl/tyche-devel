#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(kernel::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::arch::asm;
use core::panic::PanicInfo;

use kernel::memory::VirtualMemoryAreaAllocator;
use kernel::println;
use kernel::qemu;
use kernel::vmx;
use kernel::vmx::bitmaps::{
    EntryControls, EptEntryFlags, ExceptionBitmap, ExitControls, PinbasedControls, PrimaryControls,
    SecondaryControls, VmFuncControls,
};
use kernel::vmx::ept;
use kernel::vmx::fields;

use bootloader::{entry_point, BootInfo};
use kernel::vmx::fields::traits::*;
use x86_64::registers::control::{Cr0, Cr0Flags};
use x86_64::registers::model_specific::Efer;
use x86_64::VirtAddr;

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Initialize display, if any
    if let Some(buffer) = boot_info.framebuffer.as_mut().take() {
        kernel::init_display(buffer);
    }
    println!("=========== Start QEMU ===========");

    // Initialize kernel structures
    kernel::init();

    // Run tests and exit in test configuration
    #[cfg(test)]
    {
        test_main();
    }

    // Initialize memory management
    let physical_memory_offset = VirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("The bootloader must be configured with 'map-physical-memory'"),
    );

    let vma_allocator = unsafe {
        kernel::init_memory(physical_memory_offset, &mut boot_info.memory_regions)
            .expect("Failed to initialize memory")
    };

    // Start doing VMX things
    unsafe {
        initialize_cpu();
        println!("VMX:    {:?}", vmx::vmx_available());
        println!("EPT:    {:?}", vmx::ept_capabilities());
        println!("VMFunc: {:?}", vmx::available_vmfuncs());
        println!("VMXON:  {:?}", vmx::vmxon(&vma_allocator));

        let mut vmcs = match vmx::VmcsRegion::new(&vma_allocator) {
            Err(err) => {
                println!("VMCS:   Err({:?})", err);
                qemu::exit(qemu::ExitCode::Failure);
            }
            Ok(vmcs) => {
                println!("VMCS:   Ok(())");
                vmcs
            }
        };

        println!("LOAD:   {:?}", vmcs.set_as_active());
        let err = vmcs
            .set_pin_based_ctrls(PinbasedControls::empty())
            .and_then(|_| {
                vmcs.set_vm_exit_ctrls(
                    ExitControls::HOST_ADDRESS_SPACE_SIZE
                        | ExitControls::LOAD_IA32_EFER
                        | ExitControls::SAVE_IA32_EFER,
                )
            })
            .and_then(|_| {
                vmcs.set_vm_entry_ctrls(
                    EntryControls::IA32E_MODE_GUEST | EntryControls::LOAD_IA32_EFER,
                )
            })
            .and_then(|_| vmcs.set_exception_bitmap(ExceptionBitmap::empty()))
            .and_then(|_| vmcs.save_host_state())
            .and_then(|_| setup_guest(&mut vmcs.vcpu));
        println!("Config: {:?}", err);
        println!("MSRs:   {:?}", configure_msr());

        let switching = vmx::available_vmfuncs().is_ok();
        println!(
            "1'Ctrl: {:?}",
            vmcs.set_primary_ctrls(PrimaryControls::SECONDARY_CONTROLS)
        );
        println!("Switching: {}", switching);
        let mut secondary_ctrls = SecondaryControls::ENABLE_RDTSCP | SecondaryControls::ENABLE_EPT;
        if switching {
            secondary_ctrls |= SecondaryControls::ENABLE_VM_FUNCTIONS
        }
        println!("2'Ctrl: {:?}", vmcs.set_secondary_ctrls(secondary_ctrls));
        let ept_mapper =
            setup_ept(physical_memory_offset, &vma_allocator).expect("Failed to setupt EPT 1");
        println!("EPTP:   {:?}", vmcs.set_ept_ptr(&ept_mapper));

        // Let's see if we can duplicate the EPTs, and register them both
        if switching {
            let ept_mapper2 =
                setup_ept(physical_memory_offset, &vma_allocator).expect("Failed to setup EPT 2");
            println!("EPT2:   {:?}", vmcs.set_ept_ptr(&ept_mapper2));
            let mut eptp_list =
                ept::EptpList::new(&vma_allocator).expect("Failed to allocate EPTP list");
            eptp_list.set_entry(0, &ept_mapper);
            eptp_list.set_entry(1, &ept_mapper2);
            println!("EPTP L: {:?}", vmcs.set_eptp_list(&eptp_list));
            println!(
                "Enable vmfunc: {:?}",
                vmcs.set_vmfunc_ctrls(VmFuncControls::EPTP_SWITCHING)
            );
        }

        println!("Check:  {:?}", vmx::check::check());
        println!("Launch: {:?}", launch_guest(&mut vmcs, switching));
        println!("Info:   {:?}", vmcs.vcpu.interrupt_info());
        println!(
            "Qualif: {:?}",
            vmcs.vcpu
                .exit_qualification()
                .map(|qualif| qualif.ept_violation())
        );
        println!("VMXOFF: {:?}", vmx::raw::vmxoff());
    }

    kernel::qemu::exit(kernel::qemu::ExitCode::Success);
}

fn initialize_cpu() {
    // Set CPU in a valid state for VMX operations.
    let cr0 = Cr0::read();
    unsafe { Cr0::write(cr0 | Cr0Flags::NUMERIC_ERROR) };
}

fn setup_ept(
    physical_memory_offset: VirtAddr,
    allocator: &VirtualMemoryAreaAllocator,
) -> Result<vmx::ept::ExtendedPageTableMapper<impl vmx::ept::Mapper>, ()> {
    let translator = move |addr: vmx::HostPhysAddr| {
        vmx::HostVirtAddr::new(physical_memory_offset.as_u64() as usize + addr.as_usize())
    };
    let host_address_translator = unsafe { ept::HostAddressMapper::new(translator) };
    let mut ept_mapper = ept::ExtendedPageTableMapper::new(allocator, host_address_translator)
        .expect("Failed to build EPT mapper");
    let (start, end) = allocator
        .get_boundaries()
        .expect("Failed to retrieve memory boundaries");
    let capabilities = vmx::ept_capabilities().map_err(|_| ())?;

    // Just common checks on the boundaries.
    assert!(start % 0x1000 == 0);
    assert!(end % 0x1000 == 0);
    assert!(start <= end);

    // Choose the mapping page sizes
    if capabilities.contains(vmx::bitmaps::EptCapability::PAGE_1GB) {
        for i in (0..end).step_by(1 << 30) {
            unsafe {
                ept_mapper.map_giant_page(
                    allocator,
                    vmx::GuestPhysAddr::new(i as usize),
                    vmx::HostPhysAddr::new(i as usize),
                    EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
                )?
            };
        }
    } else if capabilities.contains(vmx::bitmaps::EptCapability::PAGE_2MB) {
        for i in (0..end).step_by(1 << 21) {
            unsafe {
                ept_mapper.map_huge_page(
                    allocator,
                    vmx::GuestPhysAddr::new(i as usize),
                    vmx::HostPhysAddr::new(i as usize),
                    EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
                )?
            };
        }
    } else {
        for i in (0..end).step_by(1 << 12) {
            unsafe {
                ept_mapper.map(
                    allocator,
                    vmx::GuestPhysAddr::new(i as usize),
                    vmx::HostPhysAddr::new(i as usize),
                    EptEntryFlags::READ | EptEntryFlags::WRITE | EptEntryFlags::SUPERVISOR_EXECUTE,
                )?
            };
        }
    }

    Ok(ept_mapper)
}

fn launch_guest(
    vmcs: &mut vmx::VmcsRegion,
    switching: bool,
) -> Result<vmx::VmxExitReason, vmx::VmxError> {
    const GUEST_STACK_SIZE: usize = 4096;
    let entry_point = if switching {
        guest_code_vmfunc as *const u8
    } else {
        guest_code as *const u8
    };

    let mut guest_stack = [0; GUEST_STACK_SIZE];
    let guest_rsp = guest_stack.as_mut_ptr() as usize + GUEST_STACK_SIZE;
    vmcs.vcpu
        .set_nat(fields::GuestStateNat::Rip, entry_point as usize)?;
    vmcs.vcpu.set_nat(fields::GuestStateNat::Rsp, guest_rsp)?;

    unsafe { vmcs.run() }
}

unsafe fn rdtsc() -> u64 {
        let mut hi: u64 = 0;
            let mut lo: u64 = 0;
                asm!("rdtsc", "mov {hi}, rdx", "mov {lo}, rax",
                        hi = out(reg) hi,
                                lo = out(reg) lo);
                    lo | (hi << 32)
}

fn setup_guest(vcpu: &mut vmx::VCpu) -> Result<(), vmx::VmxError> {
    // Mostly copied from https://nixhacker.com/developing-hypervisor-from-scratch-part-4/

    // Control registers
    let cr0: usize;
    let cr3: usize;
    let cr4: usize;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr0, cr0)?;
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr3, cr3)?;
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        vcpu.set_nat(fields::GuestStateNat::Cr4, cr4)?;
    }

    // Segments selectors
    let es: u16;
    let cs: u16;
    let ss: u16;
    let ds: u16;
    let fs: u16;
    let gs: u16;
    let tr: u16;
    unsafe {
        asm!("mov {:x}, es", out(reg) es, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::EsSelector, es)?;
        asm!("mov {:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::CsSelector, cs)?;
        asm!("mov {:x}, ss", out(reg) ss, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::SsSelector, ss)?;
        asm!("mov {:x}, ds", out(reg) ds, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::DsSelector, ds)?;
        asm!("mov {:x}, fs", out(reg) fs, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::FsSelector, fs)?;
        asm!("mov {:x}, gs", out(reg) gs, options(nomem, nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::GsSelector, gs)?;
        asm!("str {:x}", out(reg) tr, options(nostack, preserves_flags));
        vcpu.set16(fields::GuestState16::TrSelector, tr)?;
        vcpu.set16(fields::GuestState16::LdtrSelector, 0)?;
    }
    // println!("es 0x{:04x}", es);
    // println!("cs 0x{:04x}", cs);
    // println!("ss 0x{:04x}", ss);
    // println!("ds 0x{:04x}", ds);
    // println!("fs 0x{:04x}", fs);
    // println!("gs 0x{:04x}", gs);
    // println!("tr 0x{:04x}", tr);

    vcpu.set32(fields::GuestState32::EsAccessRights, 0xC093)?;
    vcpu.set32(fields::GuestState32::CsAccessRights, 0xA09B)?;
    vcpu.set32(fields::GuestState32::SsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::DsAccessRights, 0xC093)?;
    vcpu.set32(fields::GuestState32::FsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::GsAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::LdtrAccessRights, 0x10000)?;
    vcpu.set32(fields::GuestState32::TrAccessRights, 0x8B)?;

    let limit = 0xFFFF;
    vcpu.set32(fields::GuestState32::EsLimit, limit)?;
    vcpu.set32(fields::GuestState32::CsLimit, limit)?;
    vcpu.set32(fields::GuestState32::SsLimit, limit)?;
    vcpu.set32(fields::GuestState32::DsLimit, limit)?;
    vcpu.set32(fields::GuestState32::FsLimit, limit)?;
    vcpu.set32(fields::GuestState32::GsLimit, limit)?;
    vcpu.set32(fields::GuestState32::LdtrLimit, limit)?;
    vcpu.set32(fields::GuestState32::TrLimit, 0xff)?; // At least 0x67
    vcpu.set32(fields::GuestState32::GdtrLimit, 0xffff)?;
    vcpu.set32(fields::GuestState32::IdtrLimit, 0xffff)?;

    unsafe {
        vcpu.set_nat(fields::GuestStateNat::EsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::CsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::SsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::DsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::FsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::GsBase, 0)?;
        vcpu.set_nat(fields::GuestStateNat::LdtrBase, 0)?;
        vcpu.set_nat(
            fields::GuestStateNat::TrBase,
            fields::HostStateNat::TrBase.vmread()?,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::GdtrBase,
            fields::HostStateNat::GdtrBase.vmread()?,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::IdtrBase,
            fields::HostStateNat::IdtrBase.vmread()?,
        )?;

        // MSRs
        vcpu.set_nat(
            fields::GuestStateNat::Ia32SysenterEsp,
            fields::HostStateNat::Ia32SysenterEsp.vmread()?,
        )?;
        vcpu.set_nat(
            fields::GuestStateNat::Ia32SysenterEip,
            fields::HostStateNat::Ia32SysenterEip.vmread()?,
        )?;
        vcpu.set32(
            fields::GuestState32::Ia32SysenterCs,
            fields::HostState32::Ia32SysenterCs.vmread()?,
        )?;

        if fields::GuestState64::Ia32Efer.is_unsupported() {
            println!("Ia32Efer field is not supported");
        }
        // vcpu.set64(fields::GuestState64::Ia32Pat, fields::HostState64)
        // vcpu.set64(fields::GuestState64::Ia32Debugctl, 0)?;
        vcpu.set64(fields::GuestState64::Ia32Efer, Efer::read().bits())?;
        vcpu.set_nat(fields::GuestStateNat::Rflags, 0x2)?;
    }

    vcpu.set32(fields::GuestState32::ActivityState, 0)?;
    vcpu.set64(fields::GuestState64::VmcsLinkPtr, u64::max_value())?;
    vcpu.set16(fields::GuestState16::InterruptStatus, 0)?;
    // vcpu.set16(fields::GuestState16::PmlIndex, 0)?; // <- Not supported on dev server
    vcpu.set32(fields::GuestState32::VmxPreemptionTimerValue, 0)?;

    Ok(())
}

fn configure_msr() -> Result<(), vmx::VmxError> {
    unsafe {
        fields::Ctrl32::VmExitMsrLoadCount.vmwrite(0)?;
        fields::Ctrl32::VmExitMsrStoreCount.vmwrite(0)?;
        fields::Ctrl32::VmEntryMsrLoadCount.vmwrite(0)?;
    }

    Ok(())
}

unsafe fn guest_code_vmfunc() {
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    println!("Hello from guest!");
    let start = rdtsc();
    asm!("mov eax, 0", "mov ecx, 1", "vmfunc");
    let end = rdtsc();
    println!("After the vmfunc {} - {} = {}", end, start, end - start);
    asm!("nop", "nop", "nop", "nop", "nop", "nop", "vmcall",);
}

unsafe fn guest_code() {
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    asm!("nop", "nop", "nop", "nop", "nop", "nop");
    println!("Hello from guest!");
    asm!("nop", "nop", "nop", "nop", "nop", "nop", "vmcall",);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);

    kernel::qemu::exit(kernel::qemu::ExitCode::Failure);
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kernel::test_panic_handler(info);
}
