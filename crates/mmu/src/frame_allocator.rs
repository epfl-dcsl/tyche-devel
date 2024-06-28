//! The trait for the FrameAllocator used in both stage 1 and 2.

use utils::{Frame, HostPhysAddr, HostVirtAddr};
use vmx::GuestPhysAddr;
/// A frame allocator.
pub unsafe trait FrameAllocator {
    /// Allocates a frame.
    fn allocate_frame(&self) -> Option<Frame>;

    /// Frees a frame.
    ///
    /// The caller must give ownership of the physical frame: it must no longer be read or written
    /// by any of the code that got access to the frame.
    unsafe fn free_frame(&self, frame: HostPhysAddr) -> Result<(), ()> {
        // Default implementation: leak all the pages
        let _ = frame;
        Ok(())
    }

    /// Returns the boundaries of usable physical memory.
    fn get_boundaries(&self) -> (usize, usize);

    /// Returns the offset between physical and virtual addresses.
    fn get_physical_offset(&self) -> HostVirtAddr;
}

/// A frame allocator that can allocate contiguous ranges.
pub unsafe trait RangeAllocator: FrameAllocator {
    /// Allocates  ranges of physical memory. Uses a callback to return allocated ranges
    /// to accomodate call sites that don't have the global allocator initialized yet.
    /// The amount of ranges depends on the underlying allocator, i.e. if it uses memory coloring or not.
    ///
    /// # Arguments
    /// `size` : amount of bytes to allocate
    /// `store_cb` : Callback function that gets passed each contiguous phyiscal arange allocated by this allocator
    ///
    /// # Examples
    /// ```
    /// let mut ranges = Vec::new();
    /// let store_cb = |pr : PhysRange| {
    ///     ranges.push(pr)
    /// }
    /// allocator.allocate_range(5* 0x1000, ranges)
    /// ```
    fn allocate_range<F: FnMut(PhysRange)>(&self, size: usize, store_cb: F) -> Result<(), ()>;

    /// Returns the guest physical address where the memory from the next call to `allocate_range`
    /// would be mapped if this allocator would be "consumed/converted" to create EPT tables.
    /// Even if `allocate_range` returns scattered physical memory, they will be mapped to contiguous
    /// addresses in the guest physical address space
    fn gpa_of_next_allocation(&self) -> GuestPhysAddr;
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// A range of physical memory.
pub struct PhysRange {
    /// Start of the physical range (inclusive).
    pub start: HostPhysAddr,
    /// End of the physical range (exclusive).
    pub end: HostPhysAddr,
}

impl PhysRange {
    pub fn size(&self) -> usize {
        (self.end.as_u64() - self.start.as_u64()) as usize
    }
}
