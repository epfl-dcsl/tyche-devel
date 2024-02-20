use core::sync::atomic::*;

use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

use crate::gdt::Gdt;

pub const MAX_CPU_NUM: usize = 256;
const FALSE: AtomicBool = AtomicBool::new(false);
static CPU_INIT: [AtomicBool; MAX_CPU_NUM] = [FALSE; MAX_CPU_NUM];
const INITCPU: Option<Cpu> = None;
static mut CPUS: [Option<Cpu>; MAX_CPU_NUM] = [INITCPU; MAX_CPU_NUM];
static NB_CORES: AtomicUsize = AtomicUsize::new(0);

pub struct Cpu {
    pub id: usize,
    pub gdt: Gdt,
    pub lapic: x2apic::X2Apic,
}

impl Cpu {
    pub fn new() -> Self {
        Self {
            id: id(),
            gdt: Gdt::new(),
            lapic: x2apic::X2Apic::new(),
        }
    }

    pub fn setup(&'static mut self) {
        self.gdt.setup();
        self.lapic.init();

        initialize_cpu();

        // print VMX info on BSP
        if self.id == 0 {
            print_vmx_info();
        }
    }

    pub fn gdt(&self) -> &Gdt {
        &self.gdt
    }
}

fn initialize_cpu() {
    // Set CPU in a valid state for VMX operations.
    let cr0 = Cr0::read();
    let cr4 = Cr4::read();
    unsafe {
        Cr0::write(cr0 | Cr0Flags::NUMERIC_ERROR);
        Cr4::write(cr4 | Cr4Flags::OSXSAVE);
    };
}

fn print_vmx_info() {
    log::info!("VMX:    {:?}", vmx::vmx_available());
    log::info!("EPT:    {:?}", vmx::ept_capabilities());
    log::info!("VMFunc: {:?}", vmx::available_vmfuncs());
}

pub unsafe fn current() -> &'static mut Option<Cpu> {
    return &mut CPUS[id()];
}

pub fn init() {
    let lapic_id = id();
    assert_eq!(
        CPU_INIT[lapic_id].compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst),
        Ok(false),
        "CPU {} already initialized",
        lapic_id
    );
    // Safety: each CPU is initialized only once and by a single core.
    unsafe {
        CPUS[lapic_id] = Some(Cpu::new());
        CPUS[lapic_id].as_mut().unwrap().setup();
    }
}

pub fn set_cores(nb_cores: usize) {
    NB_CORES
        .compare_exchange(0, nb_cores, Ordering::SeqCst, Ordering::SeqCst)
        .expect("The number of cores must be set only once");
}

pub fn cores() -> usize {
    match NB_CORES.load(Ordering::SeqCst) {
        0 => panic!("Looked up the number of cores before setting it"),
        n => n,
    }
}

pub fn id() -> usize {
    let cpuid = unsafe { core::arch::x86_64::__cpuid(0x01) };
    ((cpuid.ebx & 0xffffffff) >> 24) as usize
}
