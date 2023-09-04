use super::page_allocator;
use super::utils::{num_pages, PAGE_SIZE};
use crate::arch::page_table_mapper::{KERNEL_ACCESS, USER_ACCESS};
use crate::arch::{self, VirtualAddr};
use crate::shared_buffer::bricks_debug;
pub const NUM_PAGES: usize = 16;
pub struct UserAllocator {
    pub virt_start: u64,
    pub virt_size: u64,
}

impl UserAllocator {
    pub fn malloc(&mut self, num_bytes: u64) -> VirtualAddr {
        let num_p = num_pages(num_bytes);
        let prev_virt_size = self.virt_size;
        for _ in 0..num_p {
            let (res, addr) = page_allocator::alloc_page();
            if res {
                arch::page_table_mapper::change_access(&addr, USER_ACCESS);
                if self.virt_start == 0 {
                    self.virt_start = addr.as_u64();
                }
                self.virt_size += PAGE_SIZE;
            } else {
                while self.virt_size > prev_virt_size {
                    self.virt_size -= PAGE_SIZE;
                    let addr_free = VirtualAddr::new(self.virt_start + self.virt_size);
                    arch::page_table_mapper::change_access(&addr_free, KERNEL_ACCESS);
                    page_allocator::free_page(&addr_free);
                }
                if self.virt_size == 0 {
                    self.virt_start = 0;
                }
                break;
            }
        }
        // bricks_debug(self.virt_start);
        // bricks_debug(self.virt_size);
        VirtualAddr::new(self.virt_start + self.virt_size)
    }

    pub fn free(&mut self, addr: VirtualAddr) -> VirtualAddr {
        let mut virt_end = self.virt_start + self.virt_size;
        while self.virt_size > 0 && (virt_end - PAGE_SIZE) > addr.as_u64() {
            let addr_free = VirtualAddr::new(virt_end - PAGE_SIZE);
            virt_end -= PAGE_SIZE;
            self.virt_size -= PAGE_SIZE;
            arch::page_table_mapper::change_access(&addr_free, KERNEL_ACCESS);
            page_allocator::free_page(&addr_free);
        }
        // bricks_debug(self.virt_start);
        // bricks_debug(self.virt_size);
        VirtualAddr::new(self.virt_start + self.virt_size)
    }

    pub fn new() -> Self {
        UserAllocator {
            virt_start: 0,
            virt_size: 0,
        }
    }
}
