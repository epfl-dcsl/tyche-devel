//! Empty guest

use mmu::FrameAllocator;

use super::{Guest, ManifestInfo};
use crate::{acpi::AcpiInfo, mmu::partitioned_memory_map::PartitionedMemoryMap};

pub struct VoidGuest {}

pub const VOID_GUEST: VoidGuest = VoidGuest {};

impl Guest for VoidGuest {
    unsafe fn instantiate(
        &self,
        _acpi: &AcpiInfo,
        _host_allocator: &impl FrameAllocator,
        _guest_allocator: &impl FrameAllocator,
        _color_map: &PartitionedMemoryMap,
        _rsdp: u64,
    ) -> ManifestInfo {
        ManifestInfo::default()
    }
}
