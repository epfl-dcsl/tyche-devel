use alloc::sync::Arc;
use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering};

use bootloader::boot_info::{MemoryRegion, MemoryRegionKind};
use mmu::frame_allocator::PhysRange;
use mmu::memory_coloring::{ColorRange, DummyMemoryColoring, MemoryColoring};
use mmu::ptmapper::PtMapper;
use mmu::{FrameAllocator, RangeAllocator};
use spin::Mutex;
use vmx::GuestPhysAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::PhysAddr;

use crate::second_stage::SECOND_STAGE_SIZE;
use crate::{allocator, println, vmx, HostPhysAddr, HostVirtAddr};

pub const PAGE_SIZE: usize = 0x1000;

/// How much memory to reserve for the second stage
const SECOND_STAGE_RESERVED_MEMORY: u64 = 0x1000000;
/// Gibibyte as bytes
const GIB: usize = 1 << 30;
const GUEST_RESERVED_MEMORY: usize = 2 * GIB;

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

/// How the memory is split between host and guest.
pub struct ColorMap<T: MemoryColoring + Clone> {
    /// Colors used for Dom0 VM
    pub guest: ColorRange,
    /// Colors used for Tyche (stage1, stage2)
    pub host: ColorRange,
    /// Unused Colors
    pub unused: ColorRange,
    pub coloring: T,
    ///memory map from early bootloader
    pub all_regions: &'static [MemoryRegion],
}

impl<T: MemoryColoring + Clone> ColorMap<T> {
    /// Iterates over all physical memory that belongs to the specified color_range.
    /// For each contiguous physical memory range the call back function is called
    pub fn vist_all_ranges_for_color<F: FnMut(PhysRange)>(
        &self,
        color_range: ColorRange,
        range_cb: F,
    ) {
        /* hacky use of allocator. This allocator does not "do anyhting" to the pages,
         * but simply iterates over them, adhering to the coloring and alignment requirements.
         * Here, we just use it to get the count of all frames with this color;
         * The value of the `physical_memory_offset` argument is not important here
         */
        let allocator = ColoringRangeFrameAllocator::new(
            color_range.first_color,
            color_range.color_count,
            HostVirtAddr::new(0),
            self.all_regions,
            &self.coloring,
        );
        allocator
            .allocate_range(self.guest.mem_bytes, range_cb)
            .expect("MemoryColoring::compute_ranges_for_color : alloc range failed");
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
///  - color map
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
        ColorMap<DummyMemoryColoring>,
        PtMapper<HostPhysAddr, HostVirtAddr>,
    ),
    (),
> {
    //just out of caution that using these low regions might lead to trouble
    for mr in regions.iter_mut() {
        if mr.start < 0xa0000 && mr.kind == MemoryRegionKind::Usable {
            mr.kind = MemoryRegionKind::Bootloader;
        }
    }
    // Initialize physical memory offset
    set_physical_memory_offset(physical_memory_offset);

    /* Locate memory region that has enough memory for the stage1 allocations.
     * We don't need to consider colors here, as stage1 in only used during early boot.
     * We expect that most systems will only have very coarse grained coloring.
     * Thus, it would be bad to "waste" a color here
     */
    let required_bytes_stage1_alloc = SECOND_STAGE_RESERVED_MEMORY as usize - SECOND_STAGE_SIZE;
    let mut contig_mr_for_stage1_alloc = None;
    for mr in regions.iter_mut() {
        if mr.kind == MemoryRegionKind::Usable
            && ((mr.end - mr.start) as usize > required_bytes_stage1_alloc)
        {
            let pr = PhysRange {
                start: HostPhysAddr::new(mr.start as usize),
                end: HostPhysAddr::new(mr.start as usize + required_bytes_stage1_alloc),
            };

            mr.start = pr.end.as_u64();
            assert!((mr.end - mr.start) % PAGE_SIZE as u64 == 0);
            assert!((mr.end - mr.start) >= PAGE_SIZE as u64);

            contig_mr_for_stage1_alloc = Some(pr);
            break;
        }
    }
    let contig_mr_for_stage1_alloc =
        contig_mr_for_stage1_alloc.expect("failed to find memory range for stage1 allocator");
    let stage1_allocator = RangeFrameAllocator::new(
        contig_mr_for_stage1_alloc.start,
        contig_mr_for_stage1_alloc.end,
        physical_memory_offset,
    );

    let mem_painter = DummyMemoryColoring {};
    let (first_stage2_color, stage2_color_count, state2_mem_bytes) = contig_color_range(
        regions,
        &mem_painter,
        0,
        DummyMemoryColoring::COLOR_COUNT as u64,
        SECOND_STAGE_SIZE,
    )
    .expect("failed to gather colors for stage2 allocator");
    let stage2_allocator = ColoringRangeFrameAllocator::new(
        first_stage2_color,
        stage2_color_count,
        physical_memory_offset,
        regions,
        &mem_painter,
    );

    let (first_guest_color, guest_color_count, guest_mem_bytes) = contig_color_range(
        regions,
        &mem_painter,
        first_stage2_color + stage2_color_count,
        DummyMemoryColoring::COLOR_COUNT as u64,
        GUEST_RESERVED_MEMORY,
    )
    .expect("failed to gather colors for guest memory");
    let guest_allocator = ColoringRangeFrameAllocator::new(
        first_guest_color,
        guest_color_count,
        physical_memory_offset,
        regions,
        &mem_painter,
    );

    let first_unused_color = first_guest_color + guest_color_count;
    let mut unused_mem_bytes = 0;
    for color_id in (first_unused_color as usize)..DummyMemoryColoring::COLOR_COUNT {
        unused_mem_bytes += compute_color_partition_size(regions, &mem_painter, color_id as u64);
    }

    let color_map = ColorMap {
        guest: ColorRange {
            first_color: first_guest_color,
            color_count: guest_color_count,
            mem_bytes: guest_mem_bytes,
        },
        host: ColorRange {
            // this assumes that stage1 and stage2 use adjacent color ranges
            first_color: first_stage2_color,
            color_count: stage2_color_count,
            mem_bytes: state2_mem_bytes,
        },
        unused: ColorRange {
            first_color: first_guest_color + guest_color_count,
            color_count: DummyMemoryColoring::COLOR_COUNT as u64
                - (first_guest_color + guest_color_count),
            mem_bytes: unused_mem_bytes,
        },
        coloring: mem_painter,
        all_regions: regions,
    };

    println!("created color map");

    // Initialize the frame allocator and the memory mapper.
    let (level_4_table_frame, _) = Cr3::read();
    let pt_root = HostPhysAddr::new(level_4_table_frame.start_address().as_u64() as usize);
    println!("About to create pt_mapper");
    let mut pt_mapper = PtMapper::new(physical_memory_offset.as_usize(), 0, pt_root);
    println!("created pt_mapper\nAbout to init heap");

    // Initialize the heap.
    allocator::init_heap(&mut pt_mapper, &stage1_allocator)?;
    println!("Initialized heap\nAbout to transofmr guest_allocator into shared allocator\n");
    let guest_allocator = SharedFrameAllocator::new(guest_allocator, physical_memory_offset);
    println!("init memory done");
    Ok((
        stage1_allocator,
        stage2_allocator,
        guest_allocator,
        color_map,
        pt_mapper,
    ))
}

// ———————————————————————————— Coloring Range Frame Allocator ————————————————//

#[derive(Debug, Clone, Copy)]
struct CurrentRegion {
    idx: usize,
    aligned_end: u64,
}
pub struct ColoringRangeFrameAllocator<T: MemoryColoring> {
    memory_regions: &'static [MemoryRegion],
    cur_region: Cell<CurrentRegion>,
    inside_cur_region_cursor: Cell<PhysAddr>,
    physical_memory_offset: HostVirtAddr,
    memory_coloring: T,
    //id of the first color that this allocator is allowed to use
    first_color: u64,
    //number of contiguous colors, starting at `first_color`, that this allocator may use
    color_count: u64,
    //number of pages that we have allocated so far
    allocated_pages_count: Cell<usize>,
}

impl<T: MemoryColoring + Clone> ColoringRangeFrameAllocator<T> {
    pub fn new(
        first_color: u64,
        color_count: u64,
        physical_memory_offset: HostVirtAddr,
        memory_regions: &'static [MemoryRegion],
        memory_coloring: &T,
    ) -> Self {
        let mut first_usable_region = None;
        for (mr_idx, mr) in memory_regions.as_ref().iter().enumerate() {
            if mr.kind == MemoryRegionKind::Usable {
                first_usable_region = Some(mr_idx);
                break;
            }
        }
        let cur_region_idx = first_usable_region.expect("did not find any usable region");
        let cur_mr = &memory_regions[cur_region_idx];
        let cur_phys_start = HostPhysAddr::new(cur_mr.start as usize);
        let cur_phys_end = HostPhysAddr::new(cur_mr.end as usize);
        let cur_range_start = cur_phys_start.align_up(PAGE_SIZE).as_u64();
        let cur_range_end = cur_phys_end.align_down(PAGE_SIZE).as_u64();

        Self {
            memory_regions,
            cur_region: Cell::new(CurrentRegion {
                idx: cur_region_idx,
                aligned_end: cur_range_end,
            }),
            inside_cur_region_cursor: Cell::new(PhysAddr::new(cur_range_start)),
            physical_memory_offset,
            memory_coloring: memory_coloring.clone(),
            first_color,
            color_count,
            allocated_pages_count: Cell::new(0),
        }
    }

    //advance internal state to next useable region, returns error if we ran out of regions
    fn advance_to_next_region(&self) -> Result<(), ()> {
        for (mr_idx, mr) in self
            .memory_regions
            .iter()
            .enumerate()
            .skip(self.cur_region.get().idx + 1)
        {
            if mr.kind == MemoryRegionKind::Usable {
                //update reference to current region
                self.cur_region.set(CurrentRegion {
                    idx: mr_idx,
                    aligned_end: HostPhysAddr::new(mr.end as usize)
                        .align_down(PAGE_SIZE)
                        .as_u64(),
                });
                //update reference to position inside the region to start of the new region
                let region_start = HostPhysAddr::new(mr.start as usize)
                    .align_up(PAGE_SIZE)
                    .as_u64();
                self.inside_cur_region_cursor
                    .set(PhysAddr::new(region_start));
                return Ok(());
            }
        }
        return Err(());
    }

    //get next frame inside the currently selected region or return None if we hit the end
    //DOES NOT check for color, use `next_frame_in_region_with_color` to ensure that returned frame has allowed color
    fn next_frame_in_region(&self) -> Option<vmx::Frame> {
        let cursor = self.inside_cur_region_cursor.get();
        if cursor.as_u64() < self.cur_region.get().aligned_end {
            self.inside_cur_region_cursor.set(cursor + PAGE_SIZE as u64);
            Some(vmx::Frame {
                phys_addr: vmx::HostPhysAddr::new(cursor.as_u64() as usize),
                virt_addr: (cursor.as_u64() as usize
                    + self.physical_memory_offset.as_u64() as usize),
            })
        } else {
            None
        }
    }

    //returns the next frame in the current region that has an allowed color or None if the end of the region is reached
    fn next_frame_in_region_with_color(&self) -> Option<vmx::Frame> {
        let mut next_frame = match self.next_frame_in_region() {
            Some(v) => v,
            None => return None,
        };
        let correct_color = |addr: HostPhysAddr| {
            let frame_color = self.memory_coloring.compute_color(addr);
            return (frame_color >= self.first_color)
                && (frame_color < (self.first_color + self.color_count));
        };
        while !correct_color(next_frame.phys_addr) {
            next_frame = match self.next_frame_in_region() {
                Some(v) => v,
                None => return None,
            };
        }
        if correct_color(next_frame.phys_addr) {
            return Some(next_frame);
        } else {
            return None;
        }
    }
}

unsafe impl<T: MemoryColoring + Clone> FrameAllocator for ColoringRangeFrameAllocator<T> {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let mut next_frame = self.next_frame_in_region_with_color();
        //if None, advance region and try again until we run out of regions
        while next_frame.is_none() {
            if self.advance_to_next_region().is_err() {
                return None;
            }
            next_frame = self.next_frame_in_region_with_color();
        }
        if next_frame.is_some() {
            let new_allocation_count = self.allocated_pages_count.get() + 1;
            self.allocated_pages_count.set(new_allocation_count);
        }
        return next_frame;
    }

    fn get_boundaries(&self) -> (usize, usize) {
        panic!("TODO: remove this function from trait. It is not used and does not align with the painted memory world view");
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        self.physical_memory_offset
    }
}

unsafe impl<T: MemoryColoring + Clone> RangeAllocator for ColoringRangeFrameAllocator<T> {
    fn allocate_range<F: FnMut(PhysRange)>(&self, size: usize, mut store_cb: F) -> Result<(), ()> {
        //edge case: at most one page requested
        if size <= PAGE_SIZE {
            let frame = match self.allocate_frame() {
                Some(v) => v,
                None => return Err(()),
            };
            store_cb(PhysRange {
                start: frame.phys_addr,
                end: frame.phys_addr + PAGE_SIZE,
            });
            return Ok(());
        }

        //normal case: need at least two pages for request
        let first_phy_addr = match self.allocate_frame() {
            Some(v) => v.phys_addr,
            None => return Err(()),
        };
        let mut cur_range = PhysRange {
            start: first_phy_addr,
            end: first_phy_addr + PAGE_SIZE,
        };
        /*N.B. we use signed type here as allocations might not be multiple of PAGE_SIZE
        but since we only alloc with PAGE_SIZE granularity, remaining_bytes might become negative in
        the final iteration
        */
        let mut remaining_bytes: i64 = (size - PAGE_SIZE) as i64;
        //normal case: multiple pages, allocate frames, and group them together if they are contiguous
        while remaining_bytes > 0 {
            let next = match self.allocate_frame() {
                Some(v) => v.phys_addr,
                None => return Err(()),
            };
            if next == cur_range.end {
                //Case 1: contiguous -> extend cur_range
                cur_range.end = cur_range.end + PAGE_SIZE;
            } else {
                //Case 2: not contiguous, start new range
                //ranges.push(cur_range);
                store_cb(cur_range);
                cur_range = PhysRange {
                    start: next,
                    end: next + PAGE_SIZE,
                };
            }
            remaining_bytes -= PAGE_SIZE as i64;
        }
        //store final range before returning
        store_cb(cur_range);
        Ok(())
    }

    fn gpa_of_next_allocation(&self) -> vmx::GuestPhysAddr {
        /* When creating a guest physical address space, we simply take
         * the whole memory range "owned" by an allocator an map it to
         * contiguous GPAs using the EPT. Thus, to obtain the future GPA
         * for an allocation, we simply need to count the number of pages we alloacted.
         * It does not matter that they are scattered in the host physical address space
         */
        GuestPhysAddr::new(self.allocated_pages_count.get())
    }
}

/// Compute contiguous color range required for `required_bytes` bytes
/// # Arguments
/// - `total_color_count` absolute number of colors provided by the coloring
/// # Returns
/// On succcess returns tuple (first color id, color count, size in bytes)
fn contig_color_range<T: MemoryColoring + Clone>(
    all_regions: &'static [MemoryRegion],
    coloring: &T,
    first_usable_color_id: u64,
    total_color_count: u64,
    required_bytes: usize,
) -> Result<(u64, u64, usize), ()> {
    let first_used_color = first_usable_color_id;
    let mut color_count = 1;
    let mut mem_bytes = compute_color_partition_size(all_regions, coloring, first_used_color);
    for new_color in first_usable_color_id + 1..total_color_count {
        if mem_bytes > required_bytes {
            break;
        }
        let new_color_bytes =
            compute_color_partition_size(all_regions.as_ref(), coloring, new_color as u64);
        mem_bytes += new_color_bytes;
        color_count += 1;
    }
    if mem_bytes < required_bytes {
        return Err(());
    }
    return Ok((first_used_color, color_count, mem_bytes));
}

/// Computes the size of the memory partition with the given color_id in bytes
fn compute_color_partition_size<T: MemoryColoring + Clone>(
    all_regions: &'static [MemoryRegion],
    coloring: &T,
    color_id: u64,
) -> usize {
    let mut frame_count = 0;
    /* hacky use of allocator. This allocator does not "do anyhting" to the pages,
     * but simply iterates over them, adhering to the coloring and alignment requirements.
     * Here, we just use it to get the count of all frames with this color;
     * The value of the `physical_memory_offset` argument is not important here
     */
    let allocator =
        ColoringRangeFrameAllocator::new(color_id, 1, HostVirtAddr::new(0), all_regions, coloring);
    let mut frame_opt = allocator.allocate_frame();
    while let Some(_frame) = frame_opt {
        frame_count += 1;
        frame_opt = allocator.allocate_frame();
    }
    return frame_count * PAGE_SIZE;
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

    pub fn get_boundaries(&self) -> PhysRange {
        let first_region = self.memory_map[0];
        let last_region = self.memory_map[self.memory_map.len() - 1];
        let start = HostPhysAddr::new(first_region.start as usize);
        let end = HostPhysAddr::new(last_region.end as usize);
        PhysRange { start, end }
    }
}

// ————————————————————————— Shared Frame Allocator ————————————————————————— //

#[derive(Clone)]
pub struct SharedFrameAllocator<T: MemoryColoring + Clone> {
    alloc: Arc<Mutex<ColoringRangeFrameAllocator<T>>>,
    physical_memory_offset: HostVirtAddr,
}

impl<T: MemoryColoring + Clone> SharedFrameAllocator<T> {
    pub fn new(
        alloc: ColoringRangeFrameAllocator<T>,
        physical_memory_offset: HostVirtAddr,
    ) -> Self {
        Self {
            alloc: Arc::new(Mutex::new(alloc)),
            physical_memory_offset,
        }
    }
}

unsafe impl<T: MemoryColoring + Clone> FrameAllocator for SharedFrameAllocator<T> {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let inner = self.alloc.lock();
        let frame = inner.allocate_frame()?;

        Some(vmx::Frame {
            phys_addr: vmx::HostPhysAddr::new(frame.phys_addr.as_usize()),
            virt_addr: (frame.virt_addr + self.physical_memory_offset.as_usize() as usize),
        })
    }

    fn get_boundaries(&self) -> (usize, usize) {
        todo!("remove this");
        /*let mut inner = self.alloc.lock();
        let inner = inner.deref_mut();
        let range = inner.get_boundaries();
        (range.start.as_u64() as usize, range.end.as_u64() as usize)*/
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        self.physical_memory_offset
    }
}

unsafe impl<T: MemoryColoring + Clone> RangeAllocator for SharedFrameAllocator<T> {
    fn allocate_range<F: FnMut(PhysRange)>(&self, size: usize, mut store_cb: F) -> Result<(), ()> {
        let inner = self.alloc.lock();
        inner.allocate_range(size, store_cb)
    }

    fn gpa_of_next_allocation(&self) -> GuestPhysAddr {
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

    fn get_boundaries(&self) -> (usize, usize) {
        (
            self.range_start.as_u64() as usize,
            self.range_end.as_u64() as usize,
        )
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
            //let mut res = Vec::new();
            //res.push(range);
            store_cb(range);
            Ok(())
        } else {
            Err(())
        }
    }

    fn gpa_of_next_allocation(&self) -> GuestPhysAddr {
        GuestPhysAddr::new((self.cursor.get() - self.range_start) as usize)
    }
    /*fn allocate_range(&self, size: usize) -> Option<StackList<PhysRange>> {
        let cursor = self.cursor.get();
        if cursor + size < self.range_end {
            let new_cursor = (cursor + size).align_up(PAGE_SIZE as u64);
            self.cursor.set(new_cursor);
            let range = PhysRange {
                start: HostPhysAddr::new(cursor.as_u64() as usize),
                end: HostPhysAddr::new(new_cursor.as_u64() as usize),
            };
            let list = StackList {
                data: range,
                prev: None,
            };
            Some(list)
        } else {
            None
        }
    }*/
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
