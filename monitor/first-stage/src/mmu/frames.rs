use alloc::sync::Arc;
use alloc::vec::{self, Vec};
use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering};

use bootloader::boot_info::{MemoryRegion, MemoryRegionKind};
use log::Metadata;
use mmu::coloring_range_allocator::ColoringRangeFrameAllocator;
use mmu::frame_allocator::PhysRange;
use mmu::memory_painter::{
    ActiveMemoryColoring, ColorRange, MemoryColoring, MemoryColoringType, MemoryRange,
};
use mmu::ptmapper::PtMapper;
use mmu::{FrameAllocator, RangeAllocator};
use spin::Mutex;
use utils::GuestPhysAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::PhysAddr;

use super::partitioned_memory_map::{ColorToPhysMap, PartitionedMemoryMap};
use crate::allocator::compute_heap_requirements;
use crate::second_stage::SECOND_STAGE_SIZE;
use crate::{allocator, println, vmx, HostPhysAddr, HostVirtAddr};

pub const PAGE_SIZE: usize = 0x1000;

/// Gibibyte as bytes
const GIB: usize = 1 << 30;
/// Amount of memory for dom0
const GUEST_RESERVED_MEMORY: usize = 8 * GIB;
/// Amount of memory for stage2 tyche
const SECOND_STAGE_RESERVED_MEMORY: u64 = 2 * GIB as u64;
// ————————————————————————— Physical Memory Offset ————————————————————————— //

static PHYSICAL_MEMORY_OFFSET: AtomicUsize = AtomicUsize::new(PHYSICAL_OFFSET_GUARD);

const PHYSICAL_OFFSET_GUARD: usize = usize::MAX;

/// Set the global physical memory offset.
///
/// The offset corresponds to the offset of the virtual memory with respect to the physical memory.
/// It is fixed by the bootloader and never updated afterward.
fn set_physical_memory_offset(offset: HostVirtAddr) {
    PHYSICAL_MEMORY_OFFSET
        .compare_exchange(
            PHYSICAL_OFFSET_GUARD,
            offset.as_usize(),
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .expect("Physical memory offset was initialized more than onece.");
}

/// Retrieves the global memory offset betwen virtual and physical memory.
///
/// This function should only be called after memory subsytem initialization.
pub fn get_physical_memory_offset() -> HostVirtAddr {
    let offset = PHYSICAL_MEMORY_OFFSET.load(Ordering::SeqCst);

    // Check that the offset was properly initialized
    if offset == PHYSICAL_OFFSET_GUARD {
        panic!("Tried to read global physical memory offset prior to initialization");
    }

    HostVirtAddr::new(offset)
}

// ————————————————————————— Memory Initialization —————————————————————————— //

/// How the memory is split between host and guest.
pub struct MemoryMap {
    pub guest: &'static [MemoryRegion],
    pub host: PhysRange,
}

/// Uses conditional compilation create either a coloring or a regular
/// allocator for stage2
pub unsafe fn create_stage2_allocator<T: MemoryColoring + Clone>(
    physical_memory_offset: HostVirtAddr,
    _regions: &'static [MemoryRegion],
    _mem_painter: &T,
    stage2_contig_mr: Option<PhysRange>,
) -> (impl RangeAllocator, u64, MemoryRange) {
    #[cfg(feature = "color-s2")]
    {
        let (first_stage2_color, stage2_color_count, stage2_mem_bytes) = contig_color_range(
            _regions,
            _mem_painter,
            0,
            MemoryColoringType::COLOR_COUNT as u64,
            SECOND_STAGE_SIZE,
        )
        .expect("failed to gather colors for stage2 allocator");
        let stage2_allocator = ColoringRangeFrameAllocator::new(
            first_stage2_color,
            stage2_color_count,
            physical_memory_offset,
            _regions,
            _mem_painter,
        );
        let next_free_color = first_stage2_color + stage2_color_count;
        let stage2_mem_partiton = MemoryRange::ColoredRange(ColorRange {
            first_color: first_stage2_color,
            color_count: stage2_color_count,
            mem_bytes: stage2_mem_bytes,
        });
        return (stage2_allocator, next_free_color, stage2_mem_partiton);
    }

    #[cfg(not(feature = "color-s2"))]
    {
        let stage2_contig_mr = stage2_contig_mr.expect("create_stage2_allocator called for uncolored stage 2 but no stage2_contig_mr was provided");
        println!(
            "Creating contiguous, uncolored allocator for s2. Using Range {:x?}",
            stage2_contig_mr
        );
        let stage2_allocator = RangeFrameAllocator::new(
            stage2_contig_mr.start,
            stage2_contig_mr.end,
            physical_memory_offset,
        );
        let next_free_color = 0;
        let stage2_mem_partiton = MemoryRange::SinglePhysContigRange(stage2_contig_mr);
        return (stage2_allocator, next_free_color, stage2_mem_partiton);
    }
}

/// Initializes the memory subsystem.
///
/// After success, the memory subsystem is operationnal, meaning that the global allocator is
/// availables (and thus heap allocated values such as `Box` and `Vec` can be used).
///
/// Return values:
///  - Host frame allocator
///  - Guest frame allocator
///  - memory map
///  - The host memory mapper
///
/// SAFETY: This function must be called **at most once**, and the boot info must contain a valid
/// mapping of the physical memory.
pub unsafe fn init(
    physical_memory_offset: HostVirtAddr,
    regions: &'static mut [MemoryRegion],
) -> Result<
    (
        impl RangeAllocator,
        impl RangeAllocator,
        impl RangeAllocator,
        PartitionedMemoryMap,
        PtMapper<HostPhysAddr, HostVirtAddr>,
    ),
    (),
> {
    // Initialize physical memory offset
    set_physical_memory_offset(physical_memory_offset);

    let s1_heap_bytes = compute_heap_requirements(regions, ActiveMemoryColoring {});
    println!("Need {} MiB for s1 heap", s1_heap_bytes >> 20);

    /* Locate memory region that has enough memory for the stage1 allocations.
     * We don't need to consider colors here, as stage1 in only used during early boot.
     * We expect that most systems will only have very coarse grained coloring.
     * Thus, it would be bad to "waste" a color here
     */
    let required_bytes_stage1_alloc =
        SECOND_STAGE_RESERVED_MEMORY as usize - SECOND_STAGE_SIZE + s1_heap_bytes as usize;
    println!(
        "Need {} MiB in total for s1 alloc",
        required_bytes_stage1_alloc >> 20
    );
    let stage1_contig_mr = steal_from_last(regions, required_bytes_stage1_alloc as u64)
        .expect("failed to reserve memory for stage1");
    let stage1_allocator = RangeFrameAllocator::new(
        stage1_contig_mr.start,
        stage1_contig_mr.end,
        physical_memory_offset,
    );
    println!("Stage1 range: {:x?}", stage1_contig_mr);
    let stage1_mem_partition = MemoryRange::SinglePhysContigRange(stage1_contig_mr);

    // Initialize the frame allocator and the memory mapper.
    let (level_4_table_frame, _) = Cr3::read();
    let pt_root = HostPhysAddr::new(level_4_table_frame.start_address().as_u64() as usize);
    let mut pt_mapper = PtMapper::new(physical_memory_offset.as_usize(), 0, pt_root);

    // Initialize the heap.
    allocator::init_heap(&mut pt_mapper, &stage1_allocator)?;
    println!("Heap init done");

    let merged_mrs = merge_boot_mrs(regions);
    println!("Merged boot memory regions");
    for mr in &merged_mrs {
        println!("{:x?}, {} MiB", mr, (mr.end - mr.start) >> 20);
    }

    let (merged_mrs, stage2_contig_mr) =
        reserve_memory_region(merged_mrs, SECOND_STAGE_RESERVED_MEMORY);
    let stage2_contig_mr = stage2_contig_mr.expect("failed to reserve memory for tage2");

    let stage2_allocator: RangeFrameAllocator = RangeFrameAllocator::new(
        stage2_contig_mr.start,
        stage2_contig_mr.end,
        physical_memory_offset,
    );
    let stage2_mem_partition = MemoryRange::SinglePhysContigRange(stage2_contig_mr);
    println!("Stage2 range: {:x?}", stage2_contig_mr);

    println!("Memory Regions after stage2 alloc");
    for mr in &merged_mrs {
        println!("{:x?}, {} MiB", mr, (mr.end - mr.start) >> 20);
    }

    //This parts requires initialized allocator
    //expensive walk over whole memory range
    // DO NOT MARK REGIONS AS MEMORY REGIONS AS INVALID BEYOND THIS STEP
    println!("Starting expensive paint job");
    let color_to_phys = ColorToPhysMap::new(&regions, MemoryColoringType {});
    println!("Finished paint job");

    let (guest_allocator, guest_mem_partition, unused_mem_partiton) =
        create_guest_allocator(&color_to_phys, 0, physical_memory_offset, regions);
    println!("Guest mem partition: {:?}", guest_mem_partition);

    let guest_allocator = SharedFrameAllocator::new(guest_allocator, physical_memory_offset);

    let memory_map = PartitionedMemoryMap::new(
        stage1_mem_partition,
        stage2_mem_partition,
        guest_mem_partition,
        unused_mem_partiton,
        regions,
        color_to_phys,
    );

    Ok((
        stage1_allocator,
        stage2_allocator,
        guest_allocator,
        memory_map,
        pt_mapper,
    ))
}

/// Create allocator for guest based on `color-dom0` compile time switch
/// Returns (guest allocator, guest memory range, unused memory range)
/// # Arguments
/// - `next_free_color` : This is the first color that may be used by any coloring allocator in this range.
/// In case of not coloring dom0 this should be 0
pub fn create_guest_allocator(
    color_to_phys: &ColorToPhysMap,
    next_free_color: u64,
    physical_memory_offset: HostVirtAddr,
    memory_regions: &'static [MemoryRegion],
) -> (ColoringRangeFrameAllocator, MemoryRange, MemoryRange) {
    #[cfg(feature = "color-dom0")]
    {
        log::info!("Computing number of colors required for dom0");
        let (first_guest_color, guest_color_count, guest_mem_bytes) = color_to_phys
            .contig_color_range(next_free_color, GUEST_RESERVED_MEMORY)
            .expect("failed to gather colors for guest memory");
        let s2_memory_regions = memory_regions
            .iter()
            .map(|s1_mr| PartitionedMemoryMap::bl_mr_to_s2_mr(s1_mr))
            .collect();

        let guest_allocator = ColoringRangeFrameAllocator::new(
            color_to_phys.get_color_to_phys(),
            first_guest_color,
            guest_color_count,
            physical_memory_offset,
            s2_memory_regions,
        );

        let guest_mem_partition = MemoryRange::ColoredRange(ColorRange {
            first_color: first_guest_color,
            color_count: guest_color_count,
            mem_bytes: guest_mem_bytes as usize,
        });

        let first_unused_color = first_guest_color + guest_color_count;
        let remaining_colors = MemoryColoringType::COLOR_COUNT as u64 - first_unused_color;
        let remaining_bytes =
            color_to_phys.get_color_range_size(first_unused_color, remaining_colors);
        let unused_memory_partition = MemoryRange::ColoredRange(ColorRange {
            first_color: first_unused_color,
            color_count: MemoryColoringType::COLOR_COUNT as u64 - first_unused_color,
            mem_bytes: remaining_bytes,
        });
        return (
            guest_allocator,
            guest_mem_partition,
            unused_memory_partition,
        );
    }
    #[cfg(not(feature = "color-dom0"))]
    {
        //create coloring allocator with access to all colors. This is
        //basically equal to the boot frame allocator that was previously used
        assert_eq!(
            next_free_color, 0,
            "Using uncolored dom0 assumes that whole color range is available"
        );

        //compute lowest and highest HPA that we will use to fullill allocations
        //this info is only valid in combination with the memory map, similar to coloring
        let mut guest_start_hpa = None;
        let mut guest_end_hpa = 0;
        let mut remaining_bytes = GUEST_RESERVED_MEMORY as u64;
        for mr in regions {
            if mr.kind != MemoryRegionKind::Usable {
                continue;
            }
            if guest_start_hpa.is_none() {
                guest_start_hpa = Some(mr.start);
            }
            let mr_size = mr.end - mr.start;
            //memory region is larger than remaining requires bytes
            if mr_size > remaining_bytes {
                assert_eq!(remaining_bytes as usize % PAGE_SIZE, 0);
                let early_end = mr.start + remaining_bytes;
                guest_end_hpa = early_end;
                remaining_bytes = 0;
                break;
            }

            //can use whole memory region
            remaining_bytes -= mr_size;
            guest_end_hpa = mr.end;
        }
        assert_eq!(remaining_bytes, 0, "Not enough memory to fullfill request");
        let guest_start_hpa = guest_start_hpa.expect("did not find any useable memory range");

        //allow all colors but add range filter
        let guest_allocator = ColoringRangeFrameAllocator::new(
            0,
            ActiveMemoryColoring::COLOR_COUNT as u64,
            physical_memory_offset,
            regions,
            &mem_painter,
            Some((guest_start_hpa as usize, guest_end_hpa as usize)),
        );

        let guest_mem_partition = MemoryRange::AllRamRegionInRange(RamRegionsInRange {
            range: PhysRange {
                start: HostPhysAddr::new(guest_start_hpa as usize),
                end: HostPhysAddr::new(guest_end_hpa as usize),
            },
            mem_bytes: GUEST_RESERVED_MEMORY,
        });
        let last_ram_region = regions
            .iter()
            .rev()
            .find(|v| v.kind == MemoryRegionKind::Usable)
            .unwrap();
        let unused_memory_range = PhysRange {
            start: HostPhysAddr::new(guest_start_hpa as usize),
            end: HostPhysAddr::new(last_ram_region.end as usize),
        };
        let mut unused_memory_range_size = 0;
        PartitionedMemoryMap::<T>::iterate_over_ranges_for_mem_range(
            &regions,
            unused_memory_range,
            |pr| unused_memory_range_size += pr.size(),
        );
        let unused_mem_partition = MemoryRange::AllRamRegionInRange(RamRegionsInRange {
            range: unused_memory_range,
            mem_bytes: unused_memory_range_size,
        });
        return (guest_allocator, guest_mem_partition, unused_mem_partition);
    }
}

fn steal_from_last(regions: &mut [MemoryRegion], required_bytes: u64) -> Option<PhysRange> {
    let mr = regions.last_mut().unwrap();
    if (mr.end - mr.start) < required_bytes {
        return None;
    }
    let divider = HostPhysAddr::new((mr.end - required_bytes) as usize).align_down(PAGE_SIZE);
    let pr = PhysRange {
        start: divider,
        end: HostPhysAddr::new(mr.end as usize),
    };
    mr.end = divider.as_u64();
    return Some(pr);
}

/// Search for phys contig memory in last region and cut it from the end
/// Only use this for small amount of memory to bootstrap the heap
fn merge_boot_mrs(regions: &mut [MemoryRegion]) -> Vec<MemoryRegion> {
    let mut merged = Vec::new();
    let mut cur = regions[0];
    let regions_len = regions.len();
    for (idx, mr) in regions.iter().enumerate().skip(1) {
        if mr.start == cur.end && mr.kind == cur.kind {
            cur.end = mr.end;
        } else {
            //gap -> push
            merged.push(cur);
            cur = *mr;
        }
        if idx == regions_len - 1 {
            merged.push(cur);
        }
    }
    return merged;
}

/// Searches and returns a memory region a physically contiguous memory range
/// of the requested size. `regions` is modified to make the memory unavailable to other parts of the system
fn reserve_memory_region(
    regions: Vec<MemoryRegion>,
    required_bytes: u64,
) -> (Vec<MemoryRegion>, Option<PhysRange>) {
    //search for region with sufficient size
    let mut matching_mr = None;
    for (mr_idx, mr) in regions.iter().enumerate().rev() {
        if mr.kind == MemoryRegionKind::Usable && ((mr.end - mr.start) > required_bytes) {
            matching_mr = Some(mr_idx);
            break;
        }
    }
    //split region and compute updated region list
    match &mut matching_mr {
        Some(split_idx) => {
            let mut new_regions = Vec::new();
            for idx in 0..*split_idx {
                new_regions.push(regions[idx]);
            }
            let split: MemoryRegion = regions[*split_idx];
            let divider =
                HostPhysAddr::new((split.start + required_bytes) as usize).align_up(PAGE_SIZE);

            let pr = PhysRange {
                start: HostPhysAddr::new(split.start as usize),
                end: divider,
            };
            new_regions.push(MemoryRegion {
                start: split.start,
                end: divider.as_u64(),
                kind: MemoryRegionKind::Bootloader,
            });
            new_regions.push(MemoryRegion {
                start: divider.as_u64(),
                end: split.end,
                kind: split.kind,
            });
            for idx in (*split_idx + 1)..regions.len() {
                new_regions.push(regions[idx]);
            }

            return (new_regions, Some(pr));
        }
        None => return (regions, None),
    }
}

// ———————————————————————————— Frame Allocator ————————————————————————————— //

/// A FrameAllocator that returns usable frames from the bootloader's memory map.
pub struct BootInfoFrameAllocator {
    memory_map: &'static [MemoryRegion],
    region_idx: usize,
    next_frame: u64,
}

impl BootInfoFrameAllocator {
    /// Create a FrameAllocator from the passed memory map.
    ///
    /// This function is unsafe because the caller must guarantee that the passed
    /// memory map is valid. The main requirement is that all frames that are marked
    /// as `USABLE` in it are really unused.
    pub unsafe fn init(memory_map: &'static [MemoryRegion]) -> Self {
        let region_idx = 0;
        let next_frame = memory_map[region_idx].start;
        let mut allocator = BootInfoFrameAllocator {
            memory_map,
            next_frame,
            region_idx,
        };

        // If first region is not usable, we need to move to the next usable one
        if allocator.memory_map[allocator.region_idx].kind != MemoryRegionKind::Usable {
            allocator
                .goto_next_region()
                .expect("No usable memory region");
        } else {
            log::debug!(
                "Allocating from [0x{:x}, 0x{:x}]",
                memory_map[0].start,
                memory_map[0].end
            );
        }

        // Allocate one frame, so that we don't use frame zero
        allocator
            .allocate_frame()
            .expect("Initial frame allocation failed");

        allocator
    }

    /// Allocates a single frame.
    pub fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let region = self.memory_map[self.region_idx];
        if self.next_frame >= region.end {
            if self.goto_next_region().is_ok() {
                // Retry allocation
                self.allocate_frame()
            } else {
                // All the memory is exhausted
                None
            }
        } else {
            let frame = PhysFrame::containing_address(PhysAddr::new(self.next_frame as u64));
            self.next_frame += PAGE_SIZE as u64;
            Some(frame)
        }
    }

    /// Allocates a range of physical memory
    pub fn allocate_range(&mut self, size: usize) -> Option<PhysRange> {
        let size = size as u64;
        let region = self.memory_map[self.region_idx];
        if self.next_frame + size > region.end {
            if self.goto_next_region().is_ok() {
                // Retry allocation
                self.allocate_range(size as usize)
            } else {
                // All the memory is exhausted
                None
            }
        } else {
            let start = HostPhysAddr::new(self.next_frame as usize);
            let end = HostPhysAddr::new((self.next_frame + size) as usize);
            let nb_pages = bytes_to_pages(size as usize);
            self.next_frame = self.next_frame + (nb_pages * PAGE_SIZE) as u64;
            Some(PhysRange { start, end })
        }
    }

    /// Move the cursor to the next memory region
    fn goto_next_region(&mut self) -> Result<(), ()> {
        while self.region_idx + 1 < self.memory_map.len() {
            self.region_idx += 1;

            // Check if usable
            if self.memory_map[self.region_idx].kind == MemoryRegionKind::Usable {
                log::debug!(
                    "Allocating from [0x{:x}, 0x{:x}]",
                    self.memory_map[self.region_idx].start,
                    self.memory_map[self.region_idx].end
                );
                self.next_frame = self.memory_map[self.region_idx].start;
                return Ok(());
            }
        }

        // All the memory is exhausted
        self.next_frame = self.memory_map[self.region_idx].end;
        Err(())
    }
}

// ————————————————————————— Shared Frame Allocator ————————————————————————— //

#[derive(Clone)]
pub struct SharedFrameAllocator {
    alloc: Arc<Mutex<ColoringRangeFrameAllocator>>,
    physical_memory_offset: HostVirtAddr,
}

impl SharedFrameAllocator {
    pub fn new(alloc: ColoringRangeFrameAllocator, physical_memory_offset: HostVirtAddr) -> Self {
        Self {
            alloc: Arc::new(Mutex::new(alloc)),
            physical_memory_offset,
        }
    }
}

unsafe impl FrameAllocator for SharedFrameAllocator {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let inner = self.alloc.lock();
        inner.allocate_frame()
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        self.physical_memory_offset
    }
}

unsafe impl RangeAllocator for SharedFrameAllocator {
    fn allocate_range<F: FnMut(PhysRange)>(&self, size: usize, store_cb: F) -> Result<(), ()> {
        let inner = self.alloc.lock();
        inner.allocate_range(size, store_cb)
    }

    fn gpa_of_next_allocation(&self) -> utils::GuestPhysAddr {
        let inner = self.alloc.lock();
        inner.gpa_of_next_allocation()
    }
}

// ————————————————————————— Range Frame Allocator —————————————————————————— //

pub struct RangeFrameAllocator {
    range_start: PhysAddr,
    range_end: PhysAddr,
    cursor: Cell<PhysAddr>,
    physical_memory_offset: HostVirtAddr,
}

impl RangeFrameAllocator {
    pub unsafe fn new(
        range_start: HostPhysAddr,
        range_end: HostPhysAddr,
        physical_memory_offset: HostVirtAddr,
    ) -> Self {
        log::debug!(
            "Allocator range: [0x{:x}, 0x{:x}]",
            range_start.as_usize(),
            range_end.as_usize()
        );
        let range_start = range_start.align_up(PAGE_SIZE).as_u64();
        let range_end = range_end.align_down(PAGE_SIZE).as_u64();
        Self {
            range_start: PhysAddr::new(range_start),
            range_end: PhysAddr::new(range_end),
            cursor: Cell::new(PhysAddr::new(range_start)),
            physical_memory_offset,
        }
    }
}

unsafe impl FrameAllocator for RangeFrameAllocator {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let cursor = self.cursor.get();
        if cursor.as_u64() < self.range_end.as_u64() {
            self.cursor.set(cursor + PAGE_SIZE as u64);
            Some(vmx::Frame {
                phys_addr: vmx::HostPhysAddr::new(cursor.as_u64() as usize),
                virt_addr: (cursor.as_u64() as usize
                    + self.physical_memory_offset.as_u64() as usize),
            })
        } else {
            None
        }
    }
    fn get_physical_offset(&self) -> HostVirtAddr {
        self.physical_memory_offset
    }
}

unsafe impl RangeAllocator for RangeFrameAllocator {
    fn allocate_range<F: FnMut(PhysRange)>(&self, size: usize, mut store_cb: F) -> Result<(), ()> {
        let cursor = self.cursor.get();
        if cursor + size < self.range_end {
            let new_cursor = (cursor + size).align_up(PAGE_SIZE as u64);
            self.cursor.set(new_cursor);
            let range = PhysRange {
                start: HostPhysAddr::new(cursor.as_u64() as usize),
                end: HostPhysAddr::new(new_cursor.as_u64() as usize),
            };
            store_cb(range);
            Ok(())
        } else {
            Err(())
        }
    }

    fn gpa_of_next_allocation(&self) -> utils::GuestPhysAddr {
        GuestPhysAddr::new((self.cursor.get() - self.range_start) as usize)
    }
}

// ———————————————————————————— Helper Functions ———————————————————————————— //

/// Returns the number of pages to add in order to grow by at least `n` bytes.
fn bytes_to_pages(n: usize) -> usize {
    let page_aligned = (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    page_aligned / PAGE_SIZE
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn bytes_to_pages() {
        assert_eq!(super::bytes_to_pages(0), 0);
        assert_eq!(super::bytes_to_pages(1), 1);
        assert_eq!(super::bytes_to_pages(PAGE_SIZE - 1), 1);
        assert_eq!(super::bytes_to_pages(PAGE_SIZE), 1);
        assert_eq!(super::bytes_to_pages(PAGE_SIZE + 1), 2);
    }
}
