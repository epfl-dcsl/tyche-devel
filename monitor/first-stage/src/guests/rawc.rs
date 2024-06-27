use mmu::memory_coloring::MemoryColoring;
use mmu::{IoPtMapper, RangeAllocator};
use stage_two_abi::GuestInfo;
use vtd::Iommu;

use super::Guest;
use crate::acpi::AcpiInfo;
use crate::elf::ElfProgram;
use crate::guests::ManifestInfo;
use crate::mmu::frames::PartitionedMemoryMap;
use crate::{GuestPhysAddr, GuestVirtAddr, HostVirtAddr};

#[cfg(feature = "guest_rawc")]
const RAWCBYTES: &'static [u8] = include_bytes!("../../../../guest/rawc");
#[cfg(not(feature = "guest_rawc"))]
const RAWCBYTES: &'static [u8] = &[0; 10];

const STACK: usize = 0x7ffffffdd000;

/// A datastructure to represent the program.
/// `start` is the start address of the program.
/// `offset` is the .text section offset in the raw bytes.
pub struct RawcBytes {}

pub const RAWC: RawcBytes = RawcBytes {};

impl Guest for RawcBytes {
    /// Creates a VM from the rawc file bytes and jumps.
    /// This small guest sets rax to 0x666 and performs a vmcall.
    /// It is a proof of concept on the path to instantiate a full linux vm.
    ///
    /// The strategy to instantiate it is the following:
    /// 1. Allocate page tables with one pml4 and one level 3 mapping of 1GB.
    /// 2. Copy the program rawc to this memory region.
    /// 3. Generate the EPT mappings with hpa == gpa.
    /// 4. Set the EPT and return the vmcs.
    unsafe fn instantiate<T: MemoryColoring + Clone>(
        &self,
        acpi: &AcpiInfo,
        host_allocator: &impl RangeAllocator,
        guest_allocator: &impl RangeAllocator,
        color_map: &PartitionedMemoryMap<T>,
        _rsdp: u64,
    ) -> ManifestInfo {
        let mut manifest = ManifestInfo::default();
        let rawc_prog = ElfProgram::new(RAWCBYTES);
        let virtoffset = host_allocator.get_physical_offset();

        let iopt_root = host_allocator
            .allocate_frame()
            .expect("I/O PT root allocation")
            .zeroed();
        let mut iopt_mapper = IoPtMapper::new(virtoffset.as_usize(), iopt_root.phys_addr);
        todo!("implement scatter iopt_mapper");
        /*
         let host_range = color_map.compute_host_phys_ranges();
        iopt_mapper.map_range(
            host_allocator,
            GuestPhysAddr::new(0),
            HostPhysAddr::new(0),
            host_range.start.as_usize(),
            IoPtFlag::WRITE | IoPtFlag::READ | IoPtFlag::EXECUTE,
        );*/

        // Load guest into memory.
        let mut loaded_rawc = rawc_prog
            .load::<GuestPhysAddr, GuestVirtAddr>(guest_allocator, virtoffset)
            .expect("Failed to load guest");
        let pt_root = loaded_rawc.pt_root;

        // Setup stack
        let (rsp, _stack_phys) =
            loaded_rawc.add_stack(GuestVirtAddr::new(STACK), 0x2000, guest_allocator);

        // Setup I/O MMU
        if let Some(iommus) = &acpi.iommu {
            let iommu_addr = HostVirtAddr::new(
                iommus[0].base_address.as_usize() + host_allocator.get_physical_offset().as_usize(),
            );
            let mut iommu = Iommu::new(iommu_addr);
            let root_addr = vtd::setup_iommu_context(iopt_mapper.get_root(), host_allocator);
            iommu.set_root_table_addr(root_addr.as_u64() | (0b00 << 10)); // Set legacy mode
            iommu.update_root_table_addr();
            iommu.enable_translation();
            manifest.iommu = iommus[0].base_address.as_u64();
            log::info!("I/O MMU: {:?}", iommu.get_global_status());
        }

        let entry_point = rawc_prog.entry;
        let mut info = GuestInfo::default();
        info.cr3 = pt_root.as_usize();
        info.rip = entry_point.as_usize();
        info.rsp = rsp.as_usize();
        info.rsi = 0;
        info.loaded = true;
        manifest.guest_info = info;

        manifest
    }
}
