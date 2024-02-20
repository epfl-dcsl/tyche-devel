use alloc::vec::Vec;
use core::arch::global_asm;
use core::arch::x86_64::_rdtsc;
use core::sync::atomic::*;

use acpi::platform::{PlatformInfo, Processor, ProcessorState};
use mmu::{PtFlag, PtMapper, RangeAllocator};
use x86_64::instructions::tlb;

use crate::mmu::PAGE_SIZE;
use crate::vmx::{HostPhysAddr, HostVirtAddr};
use crate::{cpu, idt, second_stage};

global_asm!(include_str!("trampoline.S"));

const START_PAGE: u8 = 7;
const ENTRY_PTR_OFFSET: u64 = 0x0ff0;
const CR3_PTR_OFFSET: u64 = 0x0ff8;
const RSP_PTR_OFFSET: u64 = 0x0fe8;

const CODE_PADDR: u64 = (START_PAGE as usize * 0x1000) as u64;
const ENTRY_PTR_PADDR: u64 = CODE_PADDR + ENTRY_PTR_OFFSET;
const CR3_PTR_PADDR: u64 = CODE_PADDR + CR3_PTR_OFFSET;
const RSP_PTR_PADDR: u64 = CODE_PADDR + RSP_PTR_OFFSET;

const FALSE: AtomicBool = AtomicBool::new(false);
static CPU_STATUS: [AtomicBool; 256] = [FALSE; 256];
pub static BSP_READY: AtomicBool = FALSE;

const STACK_SIZE: usize = 5 * 0x1000;

extern "C" {
    fn ap_trampoline_start();
    fn ap_trampoline_end();
}

fn spin(us: u64) {
    const FREQ: u64 = 2_000_000_000u64; // TODO: get cpu frequency
    let end = unsafe { _rdtsc() + FREQ / 1_000_000 * us };
    while unsafe { _rdtsc() < end } {
        core::hint::spin_loop();
    }
}

unsafe fn ap_entry() {
    // Setup GDT on the core
    cpu::init();
    // Setup IDT on the core
    idt::init();
    // Signal the AP is ready
    log::info!("CPU {}: vmx {:?}", cpu::id(), vmx::vmx_available());
    CPU_STATUS[cpu::id()].store(true, Ordering::SeqCst);
    log::info!("Hello World from cpu {}", cpu::id());
    // Wait until all cores has been initialized
    while !BSP_READY.load(Ordering::SeqCst) {
        core::hint::spin_loop();
    }
    // APs enter the 2nd stage and spins until BSP gets the manifest
    second_stage::enter();
}

/// Write the AP trampoline code to one of the 256 first frame.
///
/// The original content of the frame is backed up on another frame returned by this function.
unsafe fn allocate_code_section(
    allocator: &impl RangeAllocator,
    mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
) -> vmx::Frame {
    let phys_addr = HostPhysAddr::new(CODE_PADDR as usize);
    let backup_frame = allocator
        .allocate_frame()
        .expect("Failed to allocate a backup frame for AP trampoline code");

    // Identity map the AP boot trampoline
    mapper.map_range(
        allocator,
        HostVirtAddr::new(phys_addr.as_usize()),
        phys_addr,
        0x1000,
        PtFlag::WRITE | PtFlag::PRESENT | PtFlag::USER,
    );
    tlb::flush_all();

    // Backup the frame before writing to it.
    // The frame might be use by the bootloader, for e.g. page tables or other resources.
    // We need to restore it as soon as possible.
    let backup = core::slice::from_raw_parts_mut(backup_frame.virt_addr as *mut u8, PAGE_SIZE);
    let trampoline = core::slice::from_raw_parts(CODE_PADDR as usize as *mut u8, PAGE_SIZE);
    backup.copy_from_slice(trampoline);

    // Copy the cr3 register to cr3_ptr and share with AP
    (CR3_PTR_PADDR as *mut usize).write(x86::controlregs::cr3() as usize);
    // Copy the entry function pointer and share with AP
    (ENTRY_PTR_PADDR as *mut usize).write(ap_entry as usize);

    // Copy the ap trampoline code to start page
    core::ptr::copy_nonoverlapping(
        ap_trampoline_start as *const u8,
        CODE_PADDR as _,
        ap_trampoline_end as usize - ap_trampoline_start as usize,
    );

    backup_frame
}

/// Restore the frame used for the AP trampoline.
///
/// This might be needed as there is no guarantee the page wasn't used by the bootloader for system
/// resources (e.g. page tables).
unsafe fn restore_code_section(backup_frame: vmx::Frame) {
    let backup = core::slice::from_raw_parts(backup_frame.virt_addr as *mut u8, PAGE_SIZE);
    let trampoline = core::slice::from_raw_parts_mut(CODE_PADDR as usize as *mut u8, PAGE_SIZE);
    trampoline.copy_from_slice(backup);
}

unsafe fn allocate_stack_section(
    stack_allocator: &impl RangeAllocator,
    mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
) {
    let stack_range = stack_allocator
        .allocate_range(STACK_SIZE)
        .expect("AP stack frame");

    mapper.map_range(
        stack_allocator,
        HostVirtAddr::new(stack_range.start.as_usize()),
        stack_range.start,
        stack_range.end.as_usize() - stack_range.start.as_usize(),
        PtFlag::WRITE | PtFlag::PRESENT | PtFlag::USER,
    );

    // obviously rsp moves in the opposite direction as I expected x_x...
    (RSP_PTR_PADDR as *mut usize).write(stack_range.end.as_usize());
}

pub unsafe fn boot(
    platform_info: PlatformInfo,
    stage1_allocator: &impl RangeAllocator,
    pt_mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
) {
    let processor_info = platform_info.processor_info.as_ref().unwrap();
    let bsp: Processor = processor_info.boot_processor;
    let ap: &Vec<Processor> = processor_info.application_processors.as_ref();

    // TODO: disable PIC (mask all interrupts)

    let lapic = &mut cpu::current().as_mut().unwrap().lapic;

    // Check if I am the BSP or not
    assert!(!bsp.is_ap);
    assert!(lapic.id() == bsp.local_apic_id);

    log::info!("Setting up AP trampoline");
    let backup_frame = allocate_code_section(stage1_allocator, pt_mapper);

    // Intel MP Spec B.4: Universal Start-up Algorithm
    ap.iter().for_each(|cpu| {
        if cpu.state == ProcessorState::Disabled {
            log::error!("AP {:x?} is disabled, skip...", cpu);
        } else {
            log::info!("Waking up AP: {:x?}", cpu);
            assert!(CPU_STATUS[cpu.local_apic_id as usize].load(Ordering::SeqCst) == false);
            allocate_stack_section(stage1_allocator, pt_mapper);
            // BSP sends AP an INIT IPI (Level Interrupt)
            lapic.send_init_assert(cpu.local_apic_id);
            spin(200);
            lapic.send_init_deassert();
            // BSP delays (10ms)
            spin(10_000);
            // BSP sends AP a STARTUP IPI (1st try), AP should start executing at 000VV000h
            lapic.send_startup_ipi(cpu.local_apic_id, START_PAGE);
            // BSP delays (200us)
            spin(200);
            // BSP sends AP a STARTUP IPI (2nd try)
            lapic.send_startup_ipi(cpu.local_apic_id, START_PAGE);
            // BSP delays (200us)
            spin(200);
            // Wait for AP to startup
            spin(20000);
            // BSP verifies synchronization with executing AP
            while !CPU_STATUS[cpu.local_apic_id as usize].load(Ordering::SeqCst) {
                core::hint::spin_loop();
            }
        }
    });

    restore_code_section(backup_frame);
    cpu::set_cores(ap.len() + 1);
    log::info!("Booted {} AP.", ap.len());
}

/// Creates the wakeup page tables, that map the whole bottom 4Gb of memory. Returns the
/// corresponding cr3.
pub fn allocate_wakeup_page_tables(allocator: &impl RangeAllocator) -> u64 {
    let l4 = allocator
        .allocate_frame()
        .expect("Failed to allocate L4 wakeup PT")
        .zeroed();
    let mut mapper = PtMapper::new(allocator.get_physical_offset().as_usize(), 0, l4.phys_addr);
    mapper.map_range(
        allocator,
        HostVirtAddr::new(0),
        HostPhysAddr::new(0),
        1 << 32,
        PtFlag::PRESENT | PtFlag::WRITE | PtFlag::USER,
    );

    l4.phys_addr.as_u64()
}
