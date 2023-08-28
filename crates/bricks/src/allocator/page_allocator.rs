use x86_64::VirtAddr;
const NUM_PAGES: usize = 2;
static mut allocated: [bool; NUM_PAGES] = [false; NUM_PAGES];
const PAGE_SIZE: u64 = 0x1000;
const MEM_POOL_START: u64 = 0x500000; // this is fixed by tychools

pub fn alloc_page() -> (bool, VirtAddr) {
    for i in 0..NUM_PAGES {
        unsafe {
            if !allocated[i] {
                allocated[i] = true;
                return (true, VirtAddr::new(MEM_POOL_START + (i as u64) * PAGE_SIZE));
            }
        }
    }

    (false, VirtAddr::new(0))
}

fn check_allignment(addr: VirtAddr) -> bool {
    (addr.as_u64() % 0x1000) == 0
}

fn calc_index(addr: VirtAddr) -> u64 {
    (addr.as_u64() - MEM_POOL_START) / PAGE_SIZE
}

pub fn free_page(addr: VirtAddr) -> bool {
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
