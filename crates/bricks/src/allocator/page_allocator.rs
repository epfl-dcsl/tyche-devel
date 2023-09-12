use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::utils::PAGE_SIZE;
use crate::arch::VirtualAddr;
use crate::bricks_utils::bricks_min;

const NUM_PAGES_MAX: usize = 4;
static NUM_PAGES: AtomicUsize = AtomicUsize::new(0);
static mut allocated: [bool; NUM_PAGES_MAX] = [false; NUM_PAGES_MAX];
static MEM_POOL_START: AtomicU64 = AtomicU64::new(0);

pub fn alloc_page() -> (bool, VirtualAddr) {
    let num_pages = NUM_PAGES.load(Ordering::Relaxed);
    for i in 0..num_pages {
        unsafe {
            if !allocated[i] {
                allocated[i] = true;
                return (
                    true,
                    VirtualAddr::new(
                        MEM_POOL_START.load(Ordering::Relaxed) + (i as u64) * PAGE_SIZE,
                    ),
                );
            }
        }
    }

    (false, VirtualAddr::new(0))
}

pub fn alloc_page_back() -> (bool, VirtualAddr) {
    let num_pages = NUM_PAGES.load(Ordering::Relaxed);
    for i in (0..num_pages).rev() {
        unsafe {
            if !allocated[i] {
                allocated[i] = true;
                return (
                    true,
                    VirtualAddr::new(
                        MEM_POOL_START.load(Ordering::Relaxed) + (i as u64) * PAGE_SIZE,
                    ),
                );
            }
        }
    }

    (false, VirtualAddr::new(0))
}

fn check_allignment(addr: &VirtualAddr) -> bool {
    (addr.as_u64() % 0x1000) == 0
}

pub fn bricks_setup_allocator(start: u64, num_pages: u64) {
    MEM_POOL_START.store(start, Ordering::Relaxed);
    NUM_PAGES.store(
        bricks_min(num_pages as usize, NUM_PAGES_MAX),
        Ordering::Relaxed,
    );
}

fn calc_index(addr: &VirtualAddr) -> usize {
    (addr.as_u64() - MEM_POOL_START.load(Ordering::Relaxed)) as usize / PAGE_SIZE as usize
}

pub fn free_page(addr: &VirtualAddr) -> bool {
    if !check_allignment(addr) {
        return false;
    }
    let index = calc_index(addr);
    let num_pages = NUM_PAGES.load(Ordering::Relaxed);
    if index >= (num_pages) {
        return false;
    }
    unsafe {
        allocated[index] = false;
    }
    true
}
