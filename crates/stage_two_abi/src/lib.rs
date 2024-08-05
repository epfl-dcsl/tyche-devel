//! Second Stage ABI
//!
//! This crate defines the ABI used to bootstrap the second stage, it is intended to be consumed by
//! both the first and second stage so that they agree on a common ABI.

#![no_std]

use core::slice;

use mmu::memory_coloring::color_to_phys::MemoryRegion;
use mmu::memory_coloring::MemoryRange;
#[cfg(target_arch = "riscv64")]
use riscv_tyche::RVManifest;

// —————————————————————————————— Entry Point ——————————————————————————————— //

#[cfg(target_arch = "x86_64")]
/// Signature of the second stage entry point.
pub type EntryPoint = extern "C" fn() -> !;

/// A transparent wrapper for the entry point which enables type-checking between the first and
/// second stage.
#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! entry_point {
    ($path:path) => {
        #[no_mangle]
        pub extern "C" fn _start() -> ! {
            // Validate the signature of the entry point.
            let f: fn() -> ! = $path;
            f();
        }
    };
}

#[cfg(target_arch = "riscv64")]
/// Signature of the second stage entry point.
pub type EntryPoint = extern "C" fn(usize, RVManifest) -> !;

/// A transparent wrapper for the entry point which enables type-checking between the first and
/// second stage.
#[cfg(target_arch = "riscv64")]
#[macro_export]
macro_rules! entry_point {
    ($path:path) => {
        #[no_mangle]
        pub extern "C" fn _start(hartid: usize, manifest: RVManifest) -> ! {
            // Validate the signature of the entry point.
            let f: fn(usize, RVManifest) -> ! = $path;
            f(hartid, manifest);
        }
    };
}

/* #[cfg(all(target_arch = "riscv64", feature = "visionfive2"))]
/// Signature of the second stage entry point.
pub type EntryPoint = extern "C" fn(u64, u64, u64, u64) -> !;

/// A transparent wrapper for the entry point which enables type-checking between the first and
/// second stage.
#[cfg(all(target_arch = "riscv64", feature = "visionfive2"))]
#[macro_export]
macro_rules! entry_point {
    ($path:path) => {
        #[no_mangle]
        pub extern "C" fn _start(hartid: u64, arg1: u64, next_addr: u64, next_mode: u64) -> ! {
            // Validate the signature of the entry point.
            let f: fn(u64, u64, u64, u64) -> ! = $path;
            f(hartid, arg1, next_addr, next_mode);
        }
    };
} */

// ———————————————————————————————— Manifest ———————————————————————————————— //

/// The second stage manifest, describing the state of the system at the time the second stage is
/// entered.
#[repr(C)]
#[derive(Debug)]
pub struct Manifest {
    /// The root of the page tables for stage 2.
    pub cr3: u64,
    /// Physical offset of stage 2.
    pub poffset: u64,
    /// Virtual offset of stage 2.
    pub voffset: u64,
    /// Guest state, needed to launch the VM.
    pub info: GuestInfo,
    /// VGA infor, in case VGA screen is available.
    pub vga: VgaInfo,
    /// Optionnal address of the I/O MMU. Absent if set to 0.
    pub iommu_hva: u64,
    pub iommu_hpa: u64,
    /// SMP info:
    pub smp: Smp,
    /// Used to transfer memory regions from stage1 to stage2
    pub raw_mem_regions_slice: [u8; 4096],
    /// Number of entries in `raw_mem_regions_slice` that contains valid data
    pub raw_mem_regions_slice_valid_entries: usize,
    /// Memory exclusive to dom0
    pub dom0_memory: MemoryRange,
    /// Memory to use for other domains
    pub remaining_dom_memory: MemoryRange,
    /// If != 0, dom0 has the additional mem for usage with TDs mapped at this addr
    pub dom0_gpa_additional_mem: usize,
}

/// Suport for x86_64 SMP
#[repr(C)]
#[derive(Debug)]
pub struct Smp {
    /// SMP info: number of available cores
    pub smp: usize,
    /// ACPI MP Wakeup Mailbox Address
    pub mailbox: u64,
    /// The CR3 value for MP wakeup
    pub wakeup_cr3: u64,
}

impl Manifest {
    /// Find the symbol corresponding to the manifest and fill up the references to other
    /// static objects.
    ///
    /// SAFETY: This function must be called only once and rely on the correctness of the
    /// symbol finder.
    pub unsafe fn from_symbol_finder<F>(find_symbol: F) -> Option<&'static mut Self>
    where
        F: Fn(&str) -> Option<usize>,
    {
        // Find manifest
        let manifest = find_symbol("__manifest")?;
        let manifest = &mut *(manifest as *mut Manifest);

        Some(manifest)
    }

    /// Return parsed slice for the raw u8 memory regions stored in the Manifset
    pub fn get_boot_mem_regions(&self) -> &[MemoryRegion] {
        unsafe {
            slice::from_raw_parts(
                self.raw_mem_regions_slice.as_ptr() as *const MemoryRegion,
                self.raw_mem_regions_slice_valid_entries,
            )
        }
    }
}

// ———————————————————————————————— Statics ————————————————————————————————— //

/// Create a static manifest symbol with a well known symbol name ("__manifest").
///
/// The manifest can be retrieved with as a `&'static mut` (only once) using the `get_manifest`
/// function.
#[macro_export]
macro_rules! make_manifest {
    () => {
        pub fn get_manifest() -> &'static mut $crate::Manifest {
            use core::sync::atomic::{AtomicBool, Ordering};

            use mmu::memory_coloring::MemoryRange::ColoredRange;
            use mmu::memory_coloring::{ColorRange, MemoryRange};

            // Crearte the manifest
            #[used]
            #[export_name = "__manifest"]
            static mut __MANIFEST: $crate::Manifest = $crate::Manifest {
                cr3: 0,
                poffset: 0,
                voffset: 0,
                info: $crate::GuestInfo::default_config(),
                vga: $crate::VgaInfo::no_vga(),
                iommu_hva: 0,
                iommu_hpa: 0,
                smp: $crate::Smp {
                    smp: 0,
                    mailbox: 0,
                    wakeup_cr3: 0,
                },
                raw_mem_regions_slice: [0_u8; 4096],
                raw_mem_regions_slice_valid_entries: 0,
                /// Memory exclusive to dom0
                dom0_memory: MemoryRange::ColoredRange(ColorRange {
                    first_color: 0,
                    color_count: 0,
                    mem_bytes: 0,
                }),
                /// Memory to use for other domains
                remaining_dom_memory: MemoryRange::ColoredRange(ColorRange {
                    first_color: 0,
                    color_count: 0,
                    mem_bytes: 0,
                }),
                dom0_gpa_additional_mem: 0,
            };
            static TAKEN: AtomicBool = AtomicBool::new(false);

            /// SAFETY: We return the manifest only once. This is ensured using an atomic boolean
            /// that we set to true the first time the reference is taken.
            unsafe {
                //TODO: put back in after finding a good place to pass the manifset information down to the ept creation
                /*TAKEN
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .expect("The manifest can only be retrieved once");*/
                &mut __MANIFEST
            }
        }
    };
}

// ——————————————————————————————— Guest Info ——————————————————————————————— //

/// GuestInfo passed from stage 1 to stage 2.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct GuestInfo {
    // Guest information.
    pub cr3: usize,
    pub rip: usize,
    pub rsp: usize,
    pub rsi: usize,
    // Host segments.
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    pub efer: u64,
    // Guest is loaded
    pub loaded: bool,
}

impl GuestInfo {
    pub const fn default_config() -> Self {
        GuestInfo {
            cr3: 0,
            rip: 0,
            rsp: 0,
            rsi: 0,
            cs: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
            ss: 0,
            efer: 0,
            loaded: false,
        }
    }
}

// ———————————————————————————————— VGA Info ———————————————————————————————— //

/// VGA info passed from stage 1 to stage 2
#[repr(C)]
#[derive(Clone, Debug)]
pub struct VgaInfo {
    pub is_valid: bool,
    pub framebuffer: *mut u8,
    pub len: usize,
    pub h_rez: usize,
    pub v_rez: usize,
    pub stride: usize,
    pub bytes_per_pixel: usize,
}

impl VgaInfo {
    pub const fn no_vga() -> Self {
        Self {
            is_valid: false,
            framebuffer: 0 as *mut u8,
            len: 0,
            h_rez: 0,
            v_rez: 0,
            stride: 0,
            bytes_per_pixel: 0,
        }
    }
}
