//! A simple bump allocator based on a static bss array.
//! This should be replaced with a verified implementation.

use arena::free_list::FreeList;
pub use mmu::FrameAllocator;
use spin::Mutex;
use stage_two_abi::Manifest;
use utils::{Frame, HostPhysAddr, HostVirtAddr};

use crate::statics::NB_PAGES;

pub const PAGE_SIZE: u64 = 0x1000;
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);
pub const EMPTY_PAGE: Page = Page {
    data: [0; PAGE_SIZE as usize],
};

pub static ALLOCATOR: Allocator<NB_PAGES> = unsafe {
    Allocator {
        inner: Mutex::new(FreeListAllocator::new(PHYSICAL_PAGES)),
    }
};
static mut PHYSICAL_PAGES: [Page; NB_PAGES] = [EMPTY_PAGE; NB_PAGES];

pub fn allocator() -> &'static impl FrameAllocator {
    &ALLOCATOR
}

// ————————————————————————————————— Pages —————————————————————————————————— //

/// A 4096 bytes page.
///
/// This type is used to allocate pages, and not to actually pass around.
#[derive(Copy, Clone)]
#[repr(C, align(0x1000))]
pub struct Page {
    pub data: [u8; PAGE_SIZE as usize],
}

// —————————————————————————— Free List Allocator ——————————————————————————— //

pub struct FreeListAllocator<const N: usize> {
    /// The actual pages.
    pages: [Page; N],
    /// The free list.
    free_list: FreeList<N>,
    /// The offset of virtual memory with respect to physical.
    virt_offset: usize,
}

impl<const N: usize> FreeListAllocator<N> {
    pub const fn new(pages: [Page; N]) -> Self {
        Self {
            free_list: FreeList::new(),
            virt_offset: 0, // TODO!
            pages,
        }
    }

    /// Initializes the allocqtor.
    ///
    /// This function must be called before performing any allocation.
    pub fn initialize(&mut self, virt_offset: usize) {
        self.virt_offset = virt_offset;
    }

    /// Allocates a new frame.
    ///
    /// This function is unsafe as it assume the FreeListAllocator has been properly initialized
    /// prior to allocation. Otherwise, the Frame will contain an invalid physical address.
    pub unsafe fn allocate_frame(&mut self) -> Option<Frame> {
        let page_index = self.free_list.allocate()?;
        let frame = &mut self.pages[page_index].data as *mut u8 as u64;
        Some(Frame {
            phys_addr: HostPhysAddr::new(frame as usize - self.virt_offset),
            virt_addr: frame,
        })
    }

    /// Frees a frame.
    ///
    /// The caller must give ownership of the physical frame: it must no longer be read or written
    /// by any of the code that got access to the frame.
    unsafe fn free_frame(&mut self, frame: HostPhysAddr) {
        let phys_addr = frame.as_usize() & PAGE_MASK as usize; // Align address
        let virt_addr = phys_addr + self.virt_offset;
        let pages_start = self.pages.as_ptr() as usize;
        let page_idx = (virt_addr - pages_start) / PAGE_SIZE as usize;

        self.free_list.free(page_idx);
    }
}

pub struct Allocator<const N: usize> {
    inner: Mutex<FreeListAllocator<N>>,
}

unsafe impl<const N: usize> FrameAllocator for Allocator<N> {
    fn allocate_frame(&self) -> Option<Frame> {
        let mut inner = self.inner.lock();

        // SAFETY: We enforce that the inner allocator is properly initialized during construction
        // of the outer struct.
        unsafe { inner.allocate_frame() }
    }

    unsafe fn free_frame(&self, frame: HostPhysAddr) -> Result<(), ()> {
        let mut inner = self.inner.lock();

        unsafe { inner.free_frame(frame) };
        Ok(())
    }

    fn get_boundaries(&self) -> (usize, usize) {
        todo!("We don't need `get_boundaries` in stage 2, we should refactor our allocator trait")
    }

    fn get_physical_offset(&self) -> HostVirtAddr {
        let inner = self.inner.lock();
        HostVirtAddr::new(inner.virt_offset)
    }
}

// ————————————————————————————— Initialization ————————————————————————————— //

pub fn init(manifest: &'static Manifest) {
    let mut allocator = ALLOCATOR.inner.lock();
    allocator.initialize((manifest.voffset - manifest.poffset) as usize);
}
