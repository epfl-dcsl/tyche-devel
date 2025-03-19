extern crate alloc;
use alloc::vec::Vec;

use bootloader::boot_info::{MemoryRegion, MemoryRegionKind};
use mmu::color_to_phys_map::{self, ColorToPhysMap};
use mmu::frame_allocator::PhysRange;
use mmu::memory_painter::{
    MemoryColoring, MemoryRange, MemoryRegion as S2MemoryRegion,
    MemoryRegionKind as S2MemoryRegionKind,
};
use vmx::{GuestPhysAddr, HostPhysAddr};

use super::merged_iter::AllocHeapMergedIter;
use crate::guests::boot_params::{E820Entry, E820Types};
use crate::mmu::PAGE_SIZE;
use crate::println;

/// Describes what a certain memory area is reserved/used for
pub enum MemoryPartition {
    STAGE1,
    STAGE2,
    GUEST,
    UNUSED,
}

/// Describes the memory layout created in stage1
pub struct PartitionedMemoryMap<'a> {
    /// Memory reserved for root partition/Dom0
    pub guest: MemoryRange,
    /// Memory used for Stage 1
    pub stage1: MemoryRange,
    /// Memory used for Stage 2
    pub stage2: MemoryRange,
    /// Memory that is not allocated to any partition yet. Intended for TDs
    pub unused: MemoryRange,
    ///memory map from early bootloader
    all_regions: &'static [MemoryRegion],
    pub color_to_phys_map: ColorToPhysMap<'a>,
}

impl<'a> PartitionedMemoryMap<'a> {
    pub fn new(
        stage1_mr: MemoryRange,
        stage2_mr: MemoryRange,
        guest_mr: MemoryRange,
        unused_mr: MemoryRange,
        all_regions: &'static [MemoryRegion],
        color_to_phys_map: ColorToPhysMap<'a>,
    ) -> Self {
        Self {
            guest: guest_mr,
            stage1: stage1_mr,
            stage2: stage2_mr,
            unused: unused_mr,
            all_regions,
            color_to_phys_map,
        }
    }

    pub fn bl_mr_to_s2_mr(bl_mr: &MemoryRegion) -> S2MemoryRegion {
        S2MemoryRegion {
            start: bl_mr.start,
            end: bl_mr.end,
            kind: Self::bl_mrk_to_s2_mkr(bl_mr.kind),
        }
    }

    pub fn bl_mrk_to_s2_mkr(bl_mrk: MemoryRegionKind) -> S2MemoryRegionKind {
        match bl_mrk {
            MemoryRegionKind::Usable => S2MemoryRegionKind::UseableRAM,
            MemoryRegionKind::Bootloader
            | MemoryRegionKind::UnknownUefi(_)
            | MemoryRegionKind::UnknownBios(_) => S2MemoryRegionKind::Reserved,
            _ => panic!("Unexpected memory region kind"),
        }
    }

    pub fn print_layout(&self) {
        log::info!("guest memory range  : 0x{:x?}", self.guest);
        log::info!("stage1 memory range : 0x{:x?}", self.stage1);
        log::info!("stage2 memory range : 0x{:x?}", self.stage2);
        log::info!("unused memory       : 0x{:x?}", self.unused);
    }

    pub fn print_mem_regions(&self) {
        for (mr_idx, mr) in self.all_regions.iter().enumerate() {
            println!("idx {:02} {:x?}", mr_idx, mr);
        }
    }

    pub fn get_boot_memory_regions(&self) -> &[MemoryRegion] {
        &self.all_regions
    }

    ///Create phys ranges for all useable RAM memory in the specified range.
    /// "Useable" is defined by the passed memory region description
    pub fn iterate_over_ranges_for_mem_range<F: FnMut(PhysRange)>(
        regions: &[MemoryRegion],
        range: PhysRange,
        mut range_cb: F,
    ) {
        for mr in regions {
            //mr is before the allowed range
            if mr.end < range.start.as_u64() {
                continue;
            }
            //mr ist after allowed range, since sorted thered cannot be any more matching memory ranges
            if range.end.as_u64() < mr.start {
                break;
            }
            //mr overlaps with allowed range
            if range.start.as_u64() >= mr.start {
                //mr is completely contained
                if range.end.as_u64() >= mr.end {
                    range_cb(PhysRange {
                        start: HostPhysAddr::new(mr.start as usize),
                        end: HostPhysAddr::new(mr.end as usize),
                    });
                } else {
                    //allowed range ends in mr
                    range_cb(PhysRange {
                        start: HostPhysAddr::new(mr.start as usize),
                        end: range.end,
                    });
                }
            }
        }
    }

    /// Calls range_cb for each physical contiguous memory range that belongs to `partition`
    pub fn iterate_over_ranges_for_mem_partition<F: FnMut(PhysRange)>(
        &self,
        partition: MemoryPartition,
        mut range_cb: F,
    ) {
        let memory_range = match partition {
            MemoryPartition::STAGE1 => &self.stage1,
            MemoryPartition::STAGE2 => &self.stage2,
            MemoryPartition::GUEST => &self.guest,
            MemoryPartition::UNUSED => &self.unused,
        };

        match &memory_range {
            MemoryRange::ColoredRange(cr) => {
                //Merge the physical ranges for each color into one sorted iterator to ensure
                //that we return them int he same order, as an allocator over that range would visit them
                let mut ranges = Vec::new();
                for color_id in cr.first_color..(cr.first_color + cr.color_count) {
                    let mut v = Vec::new();
                    v.extend_from_slice(self.color_to_phys_map.get_color(color_id as usize));
                    ranges.push(v);
                }
                let merged_sorted_iter = AllocHeapMergedIter::new(ranges);
                for range in merged_sorted_iter {
                    range_cb(range);
                }
            }
            MemoryRange::SinglePhysContigRange(pr) => range_cb(*pr),
            MemoryRange::AllRamRegionInRange(rr) => {
                Self::iterate_over_ranges_for_mem_range(&self.all_regions, rr.range, range_cb)
            }
        }
    }

    /// Build memory regions for the GPA space that we will construct for the guest in stage2
    /// We need to construct them here, because we have to load them into memory and we want to avoid
    /// doing that from stage2
    /// Returns the E820 entries as well as the start addr where we put the additional mem, followed by the size of each color
    pub fn build_guest_memory_regions(&self) -> (Vec<E820Entry>, Option<Vec<usize>>) {
        /* 1) Keep Memory holes where they are (gaps between entry)
           2) Keep everything that is marked as reserved where it is (UnknownUefi(_) and UnknownBios(_))
           3) Out of caution, also Keep "Bootloader" where it is
           4) For remaining usable Regions: Mark as reserved at free will to fit the actually
           available memory
        */
        let mut result = Vec::new();

        let guest_mem_bytes = match self.guest {
            MemoryRange::ColoredRange(cr) => cr.mem_bytes,
            MemoryRange::AllRamRegionInRange(rr) => rr.mem_bytes,
            MemoryRange::SinglePhysContigRange(_) => {
                panic!("SinglePhysContigRange range is not supported for describing guest memory")
            }
        };
        let mut remaining_guest_mem_bytes = guest_mem_bytes as u64;

        let mut ram_bytes = 0;
        let mut device_bytes = 0;

        let mut highest_region_end = 0;

        for bl_mr in self.all_regions {
            highest_region_end = bl_mr.end;
            let bl_mr_bytes = bl_mr.end - bl_mr.start;
            assert_eq!(remaining_guest_mem_bytes % PAGE_SIZE as u64, 0);
            match bl_mr.kind {
                MemoryRegionKind::Usable => {
                    //No more guest memory,
                    if remaining_guest_mem_bytes <= 0 {
                        result.push(E820Entry {
                            addr: GuestPhysAddr::new(bl_mr.start as usize),
                            size: bl_mr_bytes,
                            mem_type: E820Types::Reserved,
                        });
                    //remaining guest memory is >=  bl_mr -> use whole region
                    } else if remaining_guest_mem_bytes >= bl_mr_bytes {
                        result.push(E820Entry {
                            addr: GuestPhysAddr::new(bl_mr.start as usize),
                            size: bl_mr_bytes,
                            mem_type: E820Types::Ram,
                        });
                        remaining_guest_mem_bytes -= bl_mr_bytes;
                        ram_bytes += bl_mr_bytes;
                    // remaining guest memory > 0 but smaller than region -> split region
                    } else {
                        result.push(E820Entry {
                            addr: GuestPhysAddr::new(bl_mr.start as usize),
                            size: remaining_guest_mem_bytes,
                            mem_type: E820Types::Ram,
                        });
                        result.push(E820Entry {
                            addr: GuestPhysAddr::new(
                                (bl_mr.start + remaining_guest_mem_bytes) as usize,
                            ),
                            size: bl_mr_bytes - remaining_guest_mem_bytes,
                            mem_type: E820Types::Reserved,
                        });
                        ram_bytes += remaining_guest_mem_bytes;
                        assert!(
                            remaining_guest_mem_bytes > 0
                                && remaining_guest_mem_bytes < bl_mr_bytes
                        );
                        remaining_guest_mem_bytes = 0;
                    }
                }
                //TODO: This enables some color interference, but we need it for linux to boot
                // Copy information to memory with dom0 color and hide this in the EPTs?
                MemoryRegionKind::Bootloader => {
                    result.push(E820Entry {
                        addr: GuestPhysAddr::new(bl_mr.start as usize),
                        size: bl_mr_bytes,
                        mem_type: E820Types::Ram,
                    });
                    device_bytes += bl_mr_bytes;
                }
                //passthrough
                MemoryRegionKind::UnknownUefi(_) | MemoryRegionKind::UnknownBios(_) => {
                    result.push(E820Entry {
                        addr: GuestPhysAddr::new(bl_mr.start as usize),
                        size: bl_mr_bytes,
                        mem_type: E820Types::Reserved,
                    });
                    device_bytes += bl_mr_bytes;
                }
                _ => todo!("Unknown boot loader memory type when building guest memory regions"),
            }
        }

        //tell linux about stage1 allocator memory. we use this e.g. for some ACPI data
        //It probably is enough to make sure that stage2 maps this into the EPTs but it
        //felt bettter to also include this into the boot memory map
        let stage1_alloc_mem = match self.stage1 {
            MemoryRange::ColoredRange(_) => panic!("not supported"),
            MemoryRange::SinglePhysContigRange(pcr) => pcr,
            MemoryRange::AllRamRegionInRange(_) => panic!("not supported"),
        };
        result.push(E820Entry {
            addr: GuestPhysAddr::new(stage1_alloc_mem.start.as_usize()),
            size: stage1_alloc_mem.size() as u64,
            mem_type: E820Types::Reserved,
        });

        //we pass this up to stage

        let mut additional_mem_info: Option<Vec<usize>> = None;
        //If we use memory coloring, add one E820 entry for all the memory of all additional colors at the end.
        //This ensures that Linux configures the physical addressing subsytem accordingly.
        //Mark the memory as reserved to prevent Linux from using it. Only our custom driver will touch this memory.
        match self.unused {
            MemoryRange::ColoredRange(cr) => {
                assert_ne!(highest_region_end, 0);
                assert_eq!(highest_region_end as usize % PAGE_SIZE, 0);
                //leave nice gap to make this easier to manage
                let start_gpa = GuestPhysAddr::new(highest_region_end as usize).align_up(1 << 30);
                log::info!("Start GPA for additional mem: 0x{:013x?}", start_gpa);
                let mut mem_info = Vec::new();
                mem_info.push(start_gpa.as_usize());

                let total_bytes_additiontal_colors = self
                    .color_to_phys_map
                    .get_color_range_size(cr.first_color, cr.color_count);

                let entry = E820Entry {
                    addr: start_gpa,
                    size: total_bytes_additiontal_colors as u64,
                    mem_type: E820Types::Reserved,
                };
                log::info!("Adding E820 entry for additional colors : {:x?}", entry);
                result.push(entry);
                for color_id in cr.first_color..(cr.first_color + cr.color_count) {
                    let bytes_for_color = self.color_to_phys_map.get_color_range_size(color_id, 1);
                    mem_info.push(bytes_for_color);
                }
                additional_mem_info = Some(mem_info);
            }
            _ => (),
        };

        log::info!(
            "RAM: {:0.2} GiB (0x{:x} bytes). Device {:0.2} GiB (0x{:x} bytes)",
            ram_bytes as f64 / (1 << 30) as f64,
            ram_bytes,
            device_bytes as f64 / (1 << 30) as f64,
            device_bytes
        );

        (result, additional_mem_info)
    }
}
