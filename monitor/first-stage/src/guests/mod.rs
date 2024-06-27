use mmu::memory_coloring::MemoryColoring;
use mmu::RangeAllocator;
use stage_two_abi::{GuestInfo, VgaInfo};

use crate::acpi::AcpiInfo;
use crate::mmu::frames::ColorMap;

pub mod boot_params;
pub mod linux;
pub mod rawc;
pub mod vmx;
pub mod void;

#[derive(PartialEq, Debug)]
pub enum HandlerResult {
    Resume,
    Exit,
    Crash,
}

pub struct ManifestInfo {
    pub guest_info: GuestInfo,
    pub vga_info: VgaInfo,
    pub iommu: u64,
}

impl Default for ManifestInfo {
    fn default() -> Self {
        Self {
            guest_info: Default::default(),
            vga_info: VgaInfo::no_vga(),
            iommu: Default::default(),
        }
    }
}

pub trait Guest {
    unsafe fn instantiate<T: MemoryColoring + Clone>(
        &self,
        acpi: &AcpiInfo,
        host_allocator: &impl RangeAllocator,
        guest_allocator: &impl RangeAllocator,
        color_map: &ColorMap<T>,
        rsdp: u64,
    ) -> ManifestInfo;
}
