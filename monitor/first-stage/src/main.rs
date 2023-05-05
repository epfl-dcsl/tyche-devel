#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(s1::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use acpi::AcpiTables;
use bootloader::{entry_point, BootInfo};
use log::LevelFilter;
use mmu::{PtMapper, RangeAllocator};
use s1::acpi::AcpiInfo;
use s1::acpi_handler::TycheACPIHandler;
use s1::guests::Guest;
use s1::mmu::MemoryMap;
use s1::smp::allocate_wakeup_page_tables;
use s1::{guests, println, second_stage, smp, HostPhysAddr, HostVirtAddr};
use stage_two_abi::{Smp, VgaInfo};
use x86_64::registers::control::Cr4;

const LOG_LEVEL: LevelFilter = LevelFilter::Info;

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Initialize display, if any
    let mut vga_info = VgaInfo::no_vga();
    if let Some(buffer) = boot_info.framebuffer.as_mut().take() {
        vga_info = s1::init_display(buffer);
    }
    logger::init(LOG_LEVEL);
    println!("============= First Stage =============");

    // Initialize memory management
    let physical_memory_offset = HostVirtAddr::new(
        boot_info
            .physical_memory_offset
            .into_option()
            .expect("The bootloader must be configured with 'map-physical-memory'")
            as usize,
    );
    let (host_allocator, guest_allocator, memory_map, mut pt_mapper) = unsafe {
        s1::init_memory(physical_memory_offset, &mut boot_info.memory_regions)
            .expect("Failed to initialize memory")
    };

    // Initialize kernel structures
    s1::init();

    log::info!("CR4: {:?}", Cr4::read());
    log::info!("SMX support: {:?}", s1::smx::smx_is_available());
    unsafe {
        let rax: u64;
        let rbx: u64;
        let rcx: u64;
        let rdx: u64;
        use core::arch::asm;
        asm! {
            "push rbx",
            "mov rax, 0",
            "mov rbx, 0",
            "mov rcx, 3",
            "mov rdx, 4",
            "getsec",
            "mov r10, rbx",
            "pop rbx",
            out("rax") rax,
            out("r10") rbx,
            out("rcx") rcx,
            out("rdx") rdx,
        };

        log::info!(
            "GETSEC  rax: 0x{:x} - rbx: 0x{:x} - rcx: 0x{:x} - rdx: 0x{:x}",
            rax,
            rbx,
            rcx,
            rdx
        );
    }

    // Run tests and exit in test configuration
    if cfg!(test) {
        run_tests();
    }

    // Parse RSDP tables
    let rsdp = boot_info
        .rsdp_addr
        .into_option()
        .expect("Missing RSDP address");

    let acpi_tables = match unsafe { AcpiTables::from_rsdp(TycheACPIHandler, rsdp as usize) } {
        Ok(acpi_tables) => acpi_tables,
        Err(err) => panic!("Failed to parse the ACPI table: {:?}", err),
    };

    let acpi_platform_info = match acpi_tables.platform_info() {
        Ok(platform_info) => platform_info,
        Err(err) => panic!("Unable to get platform info from the ACPI table: {:?}", err),
    };

    let mut acpi_info = unsafe { s1::acpi::AcpiInfo::from_rsdp(rsdp, physical_memory_offset) };
    let mailbox = unsafe {
        acpi_info.add_mp_wakeup_entry(
            rsdp,
            physical_memory_offset,
            &host_allocator,
            &mut pt_mapper,
        )
    };
    let wakeup_cr3 = allocate_wakeup_page_tables(&host_allocator);

    // Check I/O MMU support
    if let Some(iommus) = &acpi_info.iommu {
        let iommu_addr = HostVirtAddr::new(
            iommus[0].base_address.as_usize() + physical_memory_offset.as_usize(),
        );
        let iommu = unsafe { vtd::Iommu::new(iommu_addr) };
        log::info!("IO MMU: capabilities {:?}", iommu.get_capability(),);
        log::info!("        extended {:?}", iommu.get_extended_capability());
    } else {
        log::info!("IO MMU: None");
    }

    // Initiates the SMP boot process
    unsafe {
        smp::boot(acpi_platform_info, &host_allocator, &mut pt_mapper);
    }
    let smp_info = Smp {
        smp: s1::cpu::cores(),
        mailbox,
        wakeup_cr3,
    };

    // Enable interrupts
    x86_64::instructions::interrupts::enable();

    // Select appropriate guest depending on selected features
    if cfg!(feature = "guest_linux") {
        launch_guest(
            &guests::linux::LINUX,
            &acpi_info,
            &host_allocator,
            &guest_allocator,
            vga_info,
            memory_map,
            pt_mapper,
            rsdp as u64,
            smp_info,
        )
    } else if cfg!(feature = "guest_rawc") {
        launch_guest(
            &guests::rawc::RAWC,
            &acpi_info,
            &host_allocator,
            &guest_allocator,
            vga_info,
            memory_map,
            pt_mapper,
            rsdp as u64,
            smp_info,
        )
    } else if cfg!(feature = "no_guest") {
        launch_guest(
            &guests::void::VOID_GUEST,
            &acpi_info,
            &host_allocator,
            &guest_allocator,
            vga_info,
            memory_map,
            pt_mapper,
            rsdp as u64,
            smp_info,
        )
    } else {
        panic!("Unrecognized guest");
    }
}

fn launch_guest(
    guest: &impl Guest,
    acpi: &AcpiInfo,
    stage1_allocator: &impl RangeAllocator,
    guest_allocator: &impl RangeAllocator,
    vga_info: VgaInfo,
    memory_map: MemoryMap,
    mut pt_mapper: PtMapper<HostPhysAddr, HostVirtAddr>,
    rsdp: u64,
    smp: Smp,
) -> ! {
    let mut stage2_allocator = second_stage::second_stage_allocator(stage1_allocator);
    unsafe {
        log::info!("Loading guest");
        let mut info = guest.instantiate(
            acpi,
            &mut stage2_allocator,
            guest_allocator,
            memory_map,
            rsdp,
        );
        info.vga_info = vga_info;
        log::info!("Saving host state");
        guests::vmx::save_host_info(&mut info.guest_info);
        log::info!("Loading stage 2");
        second_stage::load(
            &info,
            stage1_allocator,
            &mut stage2_allocator,
            &mut pt_mapper,
            smp,
        );
        smp::BSP_READY.store(true, Ordering::SeqCst);
        second_stage::enter();
    }

    log::error!("Failed to jump into stage 2");
    qemu::exit(qemu::ExitCode::Failure);
    s1::hlt_loop();
}

fn run_tests() {
    #[cfg(test)]
    test_main();
    qemu::exit(qemu::ExitCode::Success);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log::error!("{}", info);

    qemu::exit(qemu::ExitCode::Failure);
    s1::hlt_loop();
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    s1::test_panic_handler(info);
    s1::hlt_loop();
}
