//! # Heap Allocator

use alloc::alloc::GlobalAlloc;
use core::sync::atomic::{AtomicBool, Ordering};

use mmu::frame_allocator::PhysRange;
use mmu::ioptmapper::PAGE_SIZE;
use mmu::{PtFlag, PtMapper, RangeAllocator};
use x86_64::instructions::tlb;

use crate::{HostPhysAddr, HostVirtAddr};

mod fallback;
mod global;
mod utils;

pub use fallback::FallbackAllocator;

pub const HEAP_START: usize = 0x4444_4444_0000;
pub const HEAP_SIZE: usize = 20 * 0x1000;

static IS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initializes the kernel heap.
pub fn init_heap(
    mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
    frame_allocator: &impl RangeAllocator,
) -> Result<(), ()> {
    if IS_INITIALIZED.swap(true, Ordering::SeqCst) {
        // Already initialized
        return Ok(());
    }

    /* as heap is not yet initialized, we cannot do dynamic allocation
     * to store the ranges. However, as the heap has a fixed size and each
     * phys range will contain at least on page, have an static sized upper boundary
     */
    let mut ranges = [PhysRange {
        start: HostPhysAddr::new(0),
        end: HostPhysAddr::new(0),
    }; HEAP_SIZE / PAGE_SIZE];
    //track the elements in `ranges` that contain valid data after allocation
    let mut ranges_next_idx = 0;
    let store_cb = |pr: PhysRange| {
        assert!(ranges_next_idx < ranges.len());
        ranges[ranges_next_idx] = pr;
        ranges_next_idx += 1;
    };
    // Find space for the heap and create the mappings
    frame_allocator
        .allocate_range(HEAP_SIZE, store_cb)
        .expect("could not allocate kernel heap");
    let mut heap_vaddr = HostVirtAddr::new(HEAP_START);
    let heap_prot = PtFlag::PRESENT | PtFlag::WRITE | PtFlag::EXEC_DISABLE;

    for range in &ranges {
        mapper.map_range(
            frame_allocator,
            heap_vaddr,
            range.start,
            range.size(),
            heap_prot,
        );
        heap_vaddr = heap_vaddr + range.size();
    }

    // SAFETY: We check that the method is called only once and the heap is valid (mappings are
    // created just above).
    unsafe {
        tlb::flush_all(); // Update page table to prevent #PF
        GLOBAL_ALLOC.lock().init(HEAP_START, HEAP_SIZE);
    }

    Ok(())
}

// —————————————————————————— The Global Allocator —————————————————————————— //

#[global_allocator]
static GLOBAL_ALLOC: utils::Locked<global::GlobalAllocator> =
    utils::Locked::new(global::GlobalAllocator::new());

unsafe impl GlobalAlloc for utils::Locked<global::GlobalAllocator> {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        self.lock().alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        self.lock().dealloc(ptr, layout)
    }
}
