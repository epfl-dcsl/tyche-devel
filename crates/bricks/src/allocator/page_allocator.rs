use crate::arch::VirtualAddr;

const NUM_PAGES: usize = 4;
static mut NUM_PAGES_DIF: usize = 4;
static mut allocated: [bool; NUM_PAGES] = [false; NUM_PAGES];
const PAGE_SIZE: u64 = 0x1000;
static mut MEM_POOL_START: u64 = 0x500000; // this is fixed by tychools

pub fn alloc_page() -> (bool, VirtualAddr) {
    let np: usize;
    unsafe {
        np = NUM_PAGES_DIF;
    }
    for i in 0..np {
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
    let np: usize;
    unsafe {
        np = NUM_PAGES_DIF;
    }
    for i in (0..np).rev() {
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

pub fn bricks_set_mem_pool_start(start: u64, num_pages: u64) {
    unsafe {
        MEM_POOL_START = start;
        NUM_PAGES_DIF = num_pages as usize;
    }
}

fn calc_index(addr: &VirtualAddr) -> u64 {
    unsafe { (addr.as_u64() - MEM_POOL_START) / PAGE_SIZE }
}

pub fn free_page(addr: &VirtualAddr) -> bool {
    let np: usize;
    unsafe {
        np = NUM_PAGES_DIF;
    }
    if !check_allignment(addr) {
        return false;
    }
    let index = calc_index(addr);
    if index >= (np as u64) {
        return false;
    }
    unsafe {
        allocated[index as usize] = false;
    }
    true
}
