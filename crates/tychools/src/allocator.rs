use std::cell::RefCell;

use mmu::FrameAllocator;
use utils::{Frame, HostPhysAddr, HostVirtAddr};

pub const PAGE_SIZE: usize = 0x1000;
pub const DEFAULT_BUMP_SIZE: usize = 500;

/// A 4096 bytes page.
///
/// This type is used to allocate pages, and not to actually pass around.
#[derive(Copy, Clone)]
#[repr(C, align(0x1000))]
pub struct Page {
    pub data: [u8; PAGE_SIZE],
}

pub struct BumpAllocator<const N: usize> {
    pub idx: usize,
    /// Physical offset where the allocator starts in the physical segment.
    pub phys_offset: usize,
    pub pages: [Page; N],
}

impl<const N: usize> BumpAllocator<N> {
    pub fn new(offset: usize) -> Self {
        Self {
            idx: 0,
            phys_offset: offset,
            pages: [Page { data: [0; 0x1000] }; N],
        }
    }

    fn allocate_frame(&mut self) -> Option<Frame> {
        if self.idx < N {
            let idx = self.idx;
            let frame = &mut self.pages[idx].data as *mut u8 as usize;
            self.idx += 1;
            return Some(Frame {
                phys_addr: HostPhysAddr::new(self.phys_offset + idx * PAGE_SIZE),
                virt_addr: frame,
            });
        }
        return None;
    }

    pub fn get_virt_offset(&self) -> usize {
        let addr = &self.pages[0].data as *const u8;
        return addr as usize;
    }
}

pub struct Allocator<'a, const N: usize> {
    inner: RefCell<&'a mut BumpAllocator<N>>,
}

impl<'a, const N: usize> Allocator<'a, N> {
    pub fn new(allocator: &'a mut BumpAllocator<N>) -> Self {
        Self {
            inner: RefCell::new(allocator),
        }
    }
}

unsafe impl<'a, const N: usize> FrameAllocator for Allocator<'a, N> {
    fn allocate_frame(&self) -> Option<Frame> {
        let mut inner = self.inner.borrow_mut();
        inner.allocate_frame()
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        todo!("Implement")
    }

    fn get_boundaries(&self) -> (usize, usize) {
        todo!("Not needed")
    }
}
