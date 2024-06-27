//! Empty guest

use mmu::memory_coloring::MemoryColoring;
use mmu::FrameAllocator;

use super::{Guest, ManifestInfo};
use crate::acpi::AcpiInfo;
use crate::mmu::frames::PartitionedMemoryMap;

pub struct VoidGuest {}

pub const VOID_GUEST: VoidGuest = VoidGuest {};

impl Guest for VoidGuest {
    unsafe fn instantiate<T: MemoryColoring + Clone>(
        &self,
        _acpi: &AcpiInfo,
        _host_allocator: &impl FrameAllocator,
        _guest_allocator: &impl FrameAllocator,
        _color_map: &PartitionedMemoryMap<T>,
        _rsdp: u64,
    ) -> ManifestInfo {
        ManifestInfo::default()
    }
}
