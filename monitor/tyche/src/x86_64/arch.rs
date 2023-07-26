//! Architecture specific structures

use core::arch::asm;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, Ordering};

use capa_engine::config::NB_CORES;

// ———————————————————— Interrupt-related Initialization ———————————————————— //

// BSP calls init to initialize IDT and GDT
pub fn init() {
    initialize_idt();
    initialize_gdt();
}

// APs should directly call setup to load IDT and GDT
pub fn setup(cpu_id: usize) {
    let gdt_desc = get_gdt_descriptor();
    let idt_desc = get_idt_descriptor();
    let tss_selector = get_tss_selector(cpu_id);

    // SAFETY: we ensure that the IDT and GDT are properly initialized prior to loading them.
    unsafe {
        asm! {
            "lgdt [{gdt}]",
            "lidt [{idt}]",
            "ltr  {tss:x}",
            gdt = in(reg) &gdt_desc,
            idt = in(reg) &idt_desc,
            tss = in(reg) tss_selector,
            options(readonly, nostack, preserves_flags),
        };
    }
}

#[repr(C, packed(2))]
pub struct DescriptorTablePointer {
    pub limit: u16,
    pub base: u64,
}

// —————————————————————————————————— GDT ——————————————————————————————————— //

/// The Global Descriptor Table.
static mut GDT: [u64; GDT_SIZE] = [0; GDT_SIZE];

/// The size of the GDT
///
/// The first entry is always unused, then we choosed the following layout:
/// - Second entry is the code segment.
/// - The next 2 * NB_CORES are the per-cpu TSS (2 entries are needed per TSS).
const GDT_SIZE: usize = 2 + 2 * NB_CORES;

/// A valid code segment for 64 bits mode.
const CODE_SEGMENT: u64 = 0xaf9b000000ffff;

/// Guard used to ensure that GDT is properly initialized before being installed.
static GDT_IS_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Guard used to ensure a single thread tries to initialize the GDT.
static GDT_IS_LOCKED: AtomicBool = AtomicBool::new(false);

/// Initializes the IDT.
///
/// This function must be called prior to accessing the IDT.
pub fn initialize_gdt() {
    GDT_IS_LOCKED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .expect("GDT is already locked!");

    // SAFETY: we hold the unique lock, so there can't be race conditions on the GDT or TSS.
    unsafe {
        GDT[1] = CODE_SEGMENT;
        for cpu_id in 0..NB_CORES {
            // Configure TSS
            let tss = EMPTY_TSS;
            // TODO: set tss.ist
            // TODO: set tss.rsp
            TSS_ARRAY[cpu_id] = tss;

            // Update the GDT with TSS entry
            let (tss_desc_low, tss_desc_high) = get_tss_descriptor(&TSS_ARRAY[cpu_id]);
            GDT[2 + 2 * cpu_id] = tss_desc_low;
            GDT[2 + 2 * cpu_id + 1] = tss_desc_high;
        }
    }

    GDT_IS_INITIALIZED.store(true, Ordering::SeqCst);
}

/// Returns a static reference to the GDT.
///
/// NOTE: the GDT must have been initialized before. This is enforced by a check which will cause a
/// panic in case initialization is not completed yet.
pub fn get_gdt() -> &'static [u64; GDT_SIZE] {
    if !GDT_IS_INITIALIZED.load(Ordering::SeqCst) {
        panic!("GDT is not yet initialized!")
    }

    // SAFETY: we ensure that the GDT was properly initialized, hence that no one will ever modify
    // it again.
    unsafe { &GDT }
}

/// Get the descriptor of the core's GDT.
#[inline]
pub fn get_gdt_descriptor() -> DescriptorTablePointer {
    let gdt = get_gdt();
    let limit = gdt.len() * size_of::<u64>() - 1;
    DescriptorTablePointer {
        limit: limit as u16,
        base: gdt.as_ptr() as u64,
    }
}

// —————————————————————————————————— TSS ——————————————————————————————————— //

/// TSS layout.
#[repr(C, packed(4))]
pub struct TaskStateSegment {
    reserved_1: u32,
    /// Address of stack pointers (RSP) for rings 0 to 2.
    rsp: [u64; 3],
    reserved_2: u64,
    /// Address of interrupt stack table (IST) pointers.
    ist: [u64; 7],
    reservec_3: u64,
    reserved_4: u16,
    io_map: u16,
}

/// An empty TSS, with default values for all fields.
const EMPTY_TSS: TaskStateSegment = TaskStateSegment {
    rsp: [0; 3],
    ist: [0; 7],
    io_map: size_of::<TaskStateSegment>() as u16,
    reserved_1: 0,
    reserved_2: 0,
    reservec_3: 0,
    reserved_4: 0,
};

/// The array of TSS, each one is supposed to be used by a different CPU.
static mut TSS_ARRAY: [TaskStateSegment; NB_CORES] = [EMPTY_TSS; NB_CORES];

/// Returns the TSS selector for a given CPU.
///
/// The TSS is a system segment, so it's descriptor is 16 bytes wide in long mode. This function
/// retuens them as a `(low, high)` pair that can be loaded into the GDT.
//
//  NOTE: see Intel manual volume 3 section 7.2.3.
fn get_tss_descriptor(tss: &TaskStateSegment) -> (u64, u64) {
    // Cast TSS pointer into integer
    let tss = tss as *const _ as u64;

    // The low and high part of the descriptor.
    let mut low = 0;
    let mut high = 0;

    // Store TSS address
    low |= get_bits(tss, 0, 23) << 16;
    low |= get_bits(tss, 24, 31) << 56;
    high |= get_bits(tss, 32, 63) << 0;

    // Store TSS size
    low |= (core::mem::size_of::<TaskStateSegment>() - 1) as u64;

    // Store TSS type
    low |= 0b1001 << 40;

    // Mark as present
    low |= 1 << 47;

    (low, high)
}

/// Returns the TSS segment selector for the given core.
pub fn get_tss_selector(cpu_id: usize) -> u16 {
    assert!(cpu_id < NB_CORES, "Invalid CPU id");
    // NOTE: the two first entries are used (null + code descriptor)
    //       then each tss selector is 2 * 8 bytes.
    (2 + 2 * cpu_id as u16) << 3
}

/// Return the bits between bottom and top (included), starting at bit 0.
fn get_bits(bits: u64, bottom: u64, top: u64) -> u64 {
    assert!(bottom < top);

    // Clear top bits
    let bits = bits << (63 - top);
    // Clear bottom bits
    bits >> (bottom + (63 - top))
}

// —————————————————————————————————— IDT ——————————————————————————————————— //

/// The unique IDT for the second stage.
static mut IDT: [IdtEntry; 256] = [IdtEntry::empty(); 256];

/// Guard used to ensure that IDT is properly initialized before being installed.
static IDT_IS_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Guard used to ensure a single thread tries to initialize the IDT.
static IDT_IS_LOCKED: AtomicBool = AtomicBool::new(false);

/// An IDT entry.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct IdtEntry {
    ptr_low: u16,
    gdt_selector: u16,
    options: u16,
    ptr_mid: u16,
    ptr_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn empty() -> Self {
        IdtEntry {
            ptr_low: 0,
            gdt_selector: 0,
            options: 0,
            ptr_mid: 0,
            ptr_high: 0,
            reserved: 0,
        }
    }
}

/// Initializes the IDT.
///
/// This function must be called prior to accessing the IDT.
pub fn initialize_idt() {
    IDT_IS_LOCKED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .expect("IDT is already locked!");

    // TODO: fill IDT entries there

    IDT_IS_INITIALIZED.store(true, Ordering::SeqCst);
}

/// Returns a static reference to the IDT.
///
/// NOTE: the IDT must have been initialized before. This is enforced by a check which will cause a
/// panic in case initialization is not completed yet.
pub fn get_idt() -> &'static [IdtEntry; 256] {
    if !IDT_IS_INITIALIZED.load(Ordering::SeqCst) {
        panic!("IDT is not yet initialized!")
    }

    // SAFETY: we ensure that the IDT was properly initialized, hence that no one will ever modify
    // it again.
    unsafe { &IDT }
}

/// Get the descriptor of the global IDT.
#[inline]
pub fn get_idt_descriptor() -> DescriptorTablePointer {
    let idt = get_idt();
    DescriptorTablePointer {
        limit: idt.len() as u16,
        base: idt.as_ptr() as u64,
    }
}
