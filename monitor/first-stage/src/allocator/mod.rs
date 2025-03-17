//! # Heap Allocator

use alloc::alloc::GlobalAlloc;
use core::sync::atomic::{AtomicBool, Ordering};

use bootloader::boot_info::{self, MemoryRegion, MemoryRegionKind};
use mmu::memory_painter::MemoryColoring;
use mmu::{PtFlag, PtMapper, RangeAllocator};
use qemu::println;
use x86_64::instructions::tlb;

use crate::{HostPhysAddr, HostVirtAddr};

mod fallback;
mod global;
mod utils;

pub use fallback::FallbackAllocator;

pub const HEAP_START: usize = 0x4444_4444_0000;
pub const HEAP_SIZE: usize = 100 * (1 << 20);

static IS_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn compute_heap_requirements<T: MemoryColoring>(
    memory_regions: &[MemoryRegion],
    painter: T,
) -> u64 {
    const BASE_SIZE: u64 = 80 * (1 << 20);
    const PER_STEP_BYTES: u64 = 16;

    let memsize: u64 = memory_regions
        .iter()
        .filter(|mr| mr.kind == MemoryRegionKind::Usable)
        .map(|mr| mr.end - mr.start)
        .sum();
    let step_size = painter.step_size();
    let additional_mem = memsize / step_size * PER_STEP_BYTES;
    println!(
        "BASE_SIZE = {} MiB, addiional_mem = {} bytes = {} MiB",
        BASE_SIZE >> 20,
        additional_mem,
        additional_mem >> 20,
    );
    BASE_SIZE + additional_mem
}

/// Initializes the kernel heap.
pub fn init_heap(
    mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
    frame_allocator: &impl RangeAllocator,
) -> Result<(), ()> {
    if IS_INITIALIZED.swap(true, Ordering::SeqCst) {
        // Already initialized
        return Ok(());
    }

    let mut heap_vaddr = HostVirtAddr::new(HEAP_START);
    let heap_prot = PtFlag::PRESENT | PtFlag::WRITE | PtFlag::EXEC_DISABLE;
    // Find space for the heap and create the mappings
    frame_allocator
        .allocate_range(HEAP_SIZE, |range| {
            mapper.map_range(
                frame_allocator,
                heap_vaddr,
                range.start,
                range.size(),
                heap_prot,
            );
            heap_vaddr = heap_vaddr + range.size();
        })
        .expect("could not allocate kernel heap");
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
