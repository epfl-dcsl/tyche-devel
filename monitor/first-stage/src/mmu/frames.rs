use alloc::sync::Arc;
use core::cell::Cell;
use core::ops::DerefMut;
use core::sync::atomic::{AtomicUsize, Ordering};

use bootloader::boot_info::{MemoryRegion, MemoryRegionKind};
use mmu::frame_allocator::PhysRange;
use mmu::ptmapper::PtMapper;
use mmu::{FrameAllocator, RangeAllocator};
use spin::Mutex;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::frame::PhysFrame;
use x86_64::PhysAddr;

use crate::{allocator, vmx, HostPhysAddr, HostVirtAddr};

pub const PAGE_SIZE: usize = 0x1000;

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
        MemoryMap,
        PtMapper<HostPhysAddr, HostVirtAddr>,
    ),
    (),
> {
    // Initialize physical memory offset
    set_physical_memory_offset(physical_memory_offset);

    // Partition physical memory between host and guest
    let host_region = select_host_region(regions);
    let host_range = PhysRange {
        start: HostPhysAddr::new(host_region.start as usize),
        end: HostPhysAddr::new(host_region.end as usize),
    };
    invalidate_higher_regions(host_region.start, regions);
    let memory_map = MemoryMap {
        guest: regions,
        host: host_range,
    };
    let mut host_allocator =
        RangeFrameAllocator::new(host_range.start, host_range.end, physical_memory_offset);
    let guest_allocator = BootInfoFrameAllocator::init(regions);

    // Initialize the frame allocator and the memory mapper.
    let (level_4_table_frame, _) = Cr3::read();
    let pt_root = HostPhysAddr::new(level_4_table_frame.start_address().as_u64() as usize);
    let mut pt_mapper = PtMapper::new(physical_memory_offset.as_usize(), 0, pt_root);

    // Initialize the heap.
    allocator::init_heap(&mut pt_mapper, &mut host_allocator)?;
    let guest_allocator = SharedFrameAllocator::new(guest_allocator, physical_memory_offset);

    Ok((host_allocator, guest_allocator, memory_map, pt_mapper))
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
pub struct SharedFrameAllocator {
    alloc: Arc<Mutex<BootInfoFrameAllocator>>,
    physical_memory_offset: HostVirtAddr,
}

impl SharedFrameAllocator {
    pub fn new(alloc: BootInfoFrameAllocator, physical_memory_offset: HostVirtAddr) -> Self {
        Self {
            alloc: Arc::new(Mutex::new(alloc)),
            physical_memory_offset,
        }
    }
}

unsafe impl FrameAllocator for SharedFrameAllocator {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        let mut inner = self.alloc.lock();
        let frame = inner.allocate_frame()?;

        Some(vmx::Frame {
            phys_addr: vmx::HostPhysAddr::new(frame.start_address().as_u64() as usize),
            virt_addr: (frame.start_address().as_u64() as usize
                + self.physical_memory_offset.as_usize() as usize),
        })
    }

    fn get_boundaries(&self) -> (usize, usize) {
        let mut inner = self.alloc.lock();
        let inner = inner.deref_mut();
        let range = inner.get_boundaries();
        (range.start.as_u64() as usize, range.end.as_u64() as usize)
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        self.physical_memory_offset
    }
}

unsafe impl RangeAllocator for SharedFrameAllocator {
    fn allocate_range(&self, size: usize) -> Option<PhysRange> {
        let mut inner = self.alloc.lock();
        inner.allocate_range(size)
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
    fn allocate_range(&self, size: usize) -> Option<PhysRange> {
        let cursor = self.cursor.get();
        if cursor + size < self.range_end {
            let new_cursor = (cursor + size).align_up(PAGE_SIZE as u64);
            self.cursor.set(new_cursor);
            Some(PhysRange {
                start: HostPhysAddr::new(cursor.as_u64() as usize),
                end: HostPhysAddr::new(new_cursor.as_u64() as usize),
            })
        } else {
            None
        }
    }
}

// ———————————————————————————— Helper Functions ———————————————————————————— //

/// Returns the number of pages to add in order to grow by at least `n` bytes.
fn bytes_to_pages(n: usize) -> usize {
    let page_aligned = (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    page_aligned / PAGE_SIZE
}

/// Selects a sub-range of the available memory regions for use within the kernel.
fn select_host_region(regions: &mut [MemoryRegion]) -> &mut MemoryRegion {
    // NOTE: We start from the end of the list (higher regions) to favor high-memory regions.
    for region in regions.iter_mut().rev() {
        // Select a free region that's big enough
        if region.kind == MemoryRegionKind::Usable && (region.end - region.start) >= 0x1000000 {
            return region;
        }
    }

    panic!("Could not find a memory region big enough");
}

/// Invalidates memory regions higher than the selected region.
fn invalidate_higher_regions(start_addr: u64, regions: &mut [MemoryRegion]) {
    for region in regions {
        if region.start >= start_addr {
            region.kind = MemoryRegionKind::UnknownBios(1);
        }
    }
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
