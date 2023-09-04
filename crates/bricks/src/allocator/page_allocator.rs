use lazy_static::lazy_static;

use super::utils::PAGE_SIZE;
use crate::arch::VirtualAddr;
use crate::bricks_utils::bricks_min;

const NUM_PAGES_MAX: usize = 4;
static mut NUM_PAGES_DIF: usize = 0;
static mut allocated: [bool; NUM_PAGES_MAX] = [false; NUM_PAGES_MAX];
static mut MEM_POOL_START: u64 = 0x500000; // this is fixed by tychools

lazy_static! {
    static ref NUM_PAGES: usize = { unsafe { bricks_min(NUM_PAGES_DIF, NUM_PAGES_MAX) } };
}

pub fn alloc_page() -> (bool, VirtualAddr) {
    for i in 0..*NUM_PAGES {
        unsafe {
            if !allocated[i] {
                allocated[i] = true;
                return (
                    true,
                    VirtualAddr::new(MEM_POOL_START + (i as u64) * PAGE_SIZE),
                );
            }
        }
    }

    (false, VirtualAddr::new(0))
}

pub fn alloc_page_back() -> (bool, VirtualAddr) {
    for i in (0..*NUM_PAGES).rev() {
        unsafe {
            if !allocated[i] {
                allocated[i] = true;
                return (
                    true,
                    VirtualAddr::new(MEM_POOL_START + (i as u64) * PAGE_SIZE),
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
    unsafe {
        MEM_POOL_START = start;
        NUM_PAGES_DIF = num_pages as usize;
    }
}

fn calc_index(addr: &VirtualAddr) -> usize {
    unsafe { (addr.as_u64() as usize - MEM_POOL_START as usize) / PAGE_SIZE as usize }
}

pub fn free_page(addr: &VirtualAddr) -> bool {
    if !check_allignment(addr) {
        return false;
    }
    let index = calc_index(addr);
    if index >= (*NUM_PAGES) {
        return false;
    }
    unsafe {
        allocated[index] = false;
    }
    true
}
