use crate::arch::VirtualAddr;

const NUM_PAGES: usize = 2;
static mut allocated: [bool; NUM_PAGES] = [false; NUM_PAGES];
const PAGE_SIZE: u64 = 0x1000;
const MEM_POOL_START: u64 = 0x500000; // this is fixed by tychools

pub fn alloc_page() -> (bool, VirtualAddr) {
    for i in 0..NUM_PAGES {
        unsafe {
            if !allocated[i] {
                allocated[i] = true;
                return (true, VirtualAddr::new(MEM_POOL_START + (i as u64) * PAGE_SIZE));
            }
        }
    }

    (false, VirtualAddr::new(0))
}

pub fn alloc_page_back() -> (bool, VirtualAddr) {
    for i in (0..NUM_PAGES).rev() {
        unsafe {
            if !allocated[i] {
                allocated[i] = true;
                return (true, VirtualAddr::new(MEM_POOL_START + (i as u64) * PAGE_SIZE));
            }
        }
    }

    (false, VirtualAddr::new(0))
}

fn check_allignment(addr: &VirtualAddr) -> bool {
    (addr.as_u64() % 0x1000) == 0
}

fn calc_index(addr: &VirtualAddr) -> u64 {
    (addr.as_u64() - MEM_POOL_START) / PAGE_SIZE
}

pub fn free_page(addr: &VirtualAddr) -> bool {
    if !check_allignment(addr) {
        return false;
    }
    let index = calc_index(addr);
    if index >= (NUM_PAGES as u64) {
        return false;
    }
    unsafe {
        allocated[index as usize] = false;
    }
    true
}
