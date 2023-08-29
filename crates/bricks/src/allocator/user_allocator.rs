use x86_64::VirtAddr;

use super::page_allocator;
use crate::arch::page_table_mapper::{KERNEL_ACCESS, USER_ACCESS};
use crate::arch::{self};
pub const NUM_PAGES: usize = 16;
pub struct UserAllocator {
    pub pages: [u64; NUM_PAGES],
    pub allocated: [bool; NUM_PAGES],
}

impl UserAllocator {
    pub fn malloc(&mut self, num_bytes: u64) -> (bool, VirtAddr) {
        let (res, addr) = page_allocator::alloc_page();
        if res {
            arch::page_table_mapper::change_access(addr, USER_ACCESS);
            for i in 0..NUM_PAGES {
                if !self.allocated[i] {
                    self.allocated[i] = true;
                    self.pages[i] = addr.as_u64();
                    return (res, addr);
                }
            }
            return (false, VirtAddr::new(0)); // should never happen ?
        }
        (res, addr)
    }

    pub fn free(&mut self, addr: VirtAddr) -> bool {
        for i in 0..NUM_PAGES {
            if self.allocated[i] && self.pages[i] == addr.as_u64() {
                arch::page_table_mapper::change_access(addr, KERNEL_ACCESS);
                self.allocated[i] = false;
                return true;
            }
        }
        false
    }

    pub fn new() -> Self {
        UserAllocator {
            pages: [0; NUM_PAGES],
            allocated: [false; NUM_PAGES],
        }
    }
}
