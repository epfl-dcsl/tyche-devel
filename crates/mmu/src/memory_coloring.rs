use utils::HostPhysAddr;

use crate::ioptmapper::PAGE_SHIFT;

///Memory colorings as described by the Magheira paper
pub trait MemoryColoring {
    /// Amount of different colors
    const COLOR_COUNT: usize;

    /// Computes the memory color for the given address
    fn compute_color(&self, frame: HostPhysAddr) -> u64;
}

/// This memory coloring is only intended as an example and does not give
/// You any isolation guarantees
#[derive(Debug, Clone)]
pub struct DummyMemoryColoring {}

impl MemoryColoring for DummyMemoryColoring {
    fn compute_color(&self, frame: HostPhysAddr) -> u64 {
        let color = (frame.as_u64() >> PAGE_SHIFT) & 0x7;
        color
    }

    const COLOR_COUNT: usize = 1 << 3;
}

#[derive(Debug, Clone, Copy)]
/// Represents a contiguous range of memory colors
pub struct ColorRange {
    /// First color in this range
    pub first_color: u64,
    /// Number of colors in in this
    /// i.e. `first_color+color_count-1` is the last used color
    pub color_count: u64,
    /// Number of bytes that this color range provides
    pub mem_bytes: usize,
}
