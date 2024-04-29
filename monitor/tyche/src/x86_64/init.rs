//! Stage 2 initialization on x86_64

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use stage_two_abi::Manifest;
use vmx::fields::VmcsField;
pub use vmx::ActiveVmcs;

use super::{arch, cpuid};
use crate::allocator;
use crate::debug::qemu;
use crate::statics::get_manifest;
use crate::x86_64::platform::MonitorX86;

// ————————————————————————————— Entry Barrier —————————————————————————————— //

/// APs will wait for the entry barrier to be `true` before jumping into stage 2.
#[used]
#[export_name = "__entry_barrier"]
static ENTRY_BARRIER: AtomicBool = AtomicBool::new(false);

// ————————————————————————————— Initialization ————————————————————————————— //

const FALSE: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = FALSE;
pub static NB_BOOTED_CORES: AtomicUsize = AtomicUsize::new(0);
static mut MANIFEST: Option<&'static Manifest> = None;

pub fn arch_entry_point(log_level: log::LevelFilter) -> ! {
    let cpuid = cpuid();

    if cpuid == 0 {
        logger::init(log_level);
        log::info!("CPU{}: Hello from second stage!", cpuid);
        #[cfg(feature = "bare_metal")]
        log::info!("Running on bare metal");

        // SAFETY: The BSP is responsible for retrieving the manifest
        let manifest = unsafe {
            MANIFEST = Some(get_manifest());
            MANIFEST.as_ref().unwrap()
        };

        init_arch(manifest, 0);
        allocator::init(manifest);
        // SAFETY: only called once on the BSP
        let mut monitor = MonitorX86 {};
        let (state, domain) = MonitorX86::init(manifest, true);

        log::info!("Waiting for {} cores", manifest.smp.smp);
        while NB_BOOTED_CORES.load(Ordering::SeqCst) + 1 < manifest.smp.smp {
            core::hint::spin_loop();
        }
        log::info!("Stage 2 initialized");

        // Mark the BSP as ready to launch guest on all APs.
        BSP_READY.store(true, Ordering::SeqCst);

        // Launch guest and exit
        monitor.launch_guest(manifest, state, domain);
        qemu::exit(qemu::ExitCode::Success);
    }
    // The APs spin until the manifest is fetched, and then initialize the second stage
    else {
        log::info!("CPU{}: Hello from second stage!", cpuid);

        // SAFETY: we only perform read accesses and we ensure the BSP initialized the manifest.
        let manifest = unsafe {
            assert!(!MANIFEST.is_none());
            MANIFEST.as_ref().unwrap()
        };

        init_arch(manifest, cpuid);

        // Wait until the BSP mark second stage as initialized (e.g. all APs are up).
        NB_BOOTED_CORES.fetch_add(1, Ordering::SeqCst);
        while !BSP_READY.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }

        log::info!("CPU{}: Waiting on mailbox", cpuid);

        // SAFETY: only called once on the BSP
        let mut monitor = MonitorX86 {};
        let (state, domain) = unsafe {
            let (mut state, domain) = MonitorX86::init(manifest, false);
            wait_on_mailbox(manifest, &mut state.vcpu, cpuid);
            (state, domain)
        };

        // Launch guest and exit
        monitor.launch_guest(manifest, state, domain);
        qemu::exit(qemu::ExitCode::Success);
    }
}
/// Architecture specific initialization.
pub fn init_arch(manifest: &Manifest, cpuid: usize) {
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) manifest.cr3,
            options(nomem, nostack, preserves_flags)
        );
        if cpuid == 0 {
            arch::init();
        }
        arch::setup(cpuid);
    }

    // In case we use VGA, setup the VGA driver
    #[cfg(feature = "vga")]
    if manifest.vga.is_valid {
        let framebuffer =
            unsafe { core::slice::from_raw_parts_mut(manifest.vga.framebuffer, manifest.vga.len) };
        let writer = vga::Writer::new(
            framebuffer,
            manifest.vga.h_rez,
            manifest.vga.v_rez,
            manifest.vga.stride,
            manifest.vga.bytes_per_pixel,
        );
        vga::init_print(writer);
    }

    // The ENTRY_BARRIER is consumed (set to false) when an AP enters stage 2, once stage 2
    // initialization is done, the AP set the ENTRY_BARRIER back to true.
    ENTRY_BARRIER
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .expect("Unexpected ENTRY_BARRIER value");
}

// ——————————————————————————————— Multi-Core ——————————————————————————————— //

unsafe fn wait_on_mailbox(manifest: &Manifest, vcpu: &mut ActiveVmcs<'static>, cpuid: usize) {
    // Spin on the MP Wakeup Page command
    let mp_mailbox = manifest.smp.mailbox as usize;
    let command = mp_mailbox as *const u16;
    let apic_id = (mp_mailbox + 4) as *const u32;
    loop {
        if command.read_volatile() == 1 && apic_id.read_volatile() == (cpuid as u32) {
            break;
        }
        core::hint::spin_loop();
    }

    let wakeup_vector = (mp_mailbox + 8) as *const u64;
    let wakeup_vector = wakeup_vector.read_volatile();
    log::info!(
        "Launching CPU {} on wakeup_vector 0x{:x}",
        cpuid,
        wakeup_vector
    );

    // Set RIP entry point
    vcpu.set(VmcsField::GuestRip, wakeup_vector as usize)
        .unwrap();
    vcpu.set(VmcsField::GuestCr3, manifest.smp.wakeup_cr3 as usize)
        .unwrap();

    (mp_mailbox as *mut u16).write_volatile(0);
}
