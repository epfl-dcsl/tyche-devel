use super::page_allocator;
use super::utils::{num_pages, PAGE_SIZE};
use crate::arch::page_table_mapper::{KERNEL_ACCESS, USER_ACCESS};
use crate::arch::{self, VirtualAddr};

pub const NUM_PAGES: usize = 16;
pub struct UserAllocator {
    pub virt_start: u64,
    pub virt_size: u64,
}

// Support for sbrk and brk calls
impl UserAllocator {
    pub fn malloc(&mut self, num_bytes: u64) -> VirtualAddr {
        let num_p = num_pages(num_bytes);
        let prev_virt_size = self.virt_size;
        for _ in 0..num_p {
            if let Ok(addr) = page_allocator::alloc_page() {
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
        VirtualAddr::new(self.virt_start + self.virt_size)
    }

    pub const fn new() -> Self {
        UserAllocator {
            virt_start: 0,
            virt_size: 0,
        }
    }
}
