use core::cell::Cell;

use vmx::HostPhysAddr;
use x86_64::addr::align_up;
use x86_64::align_down;

use super::{MemoryColoring, PartitionBitmap};
use crate::ioptmapper::PAGE_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionKind {
    UseableRAM,
    Reserved,
}

/// Represent a physical memory region.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(C)]
pub struct MemoryRegion {
    /// The physical start address of the region.
    pub start: u64,
    /// The physical end address (exclusive) of the region.
    pub end: u64,
    pub kind: MemoryRegionKind,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
/// A range of physical memory.
pub struct PhysRange {
    /// Start of the physical range (inclusive).
    pub start: usize,
    /// End of the physical range (exclusive).
    pub end: usize,
}

impl PhysRange {
    pub fn size(&self) -> usize {
        self.end - self.start
    }
}

#[derive(Debug, Clone, Copy)]
struct CurrentRegion {
    idx: usize,
    aligned_end: u64,
}

pub struct ColorToPhys<T: MemoryColoring> {
    memory_regions: &'static [MemoryRegion],
    cur_region: Cell<CurrentRegion>,
    inside_cur_region_cursor: Cell<usize>,
    memory_coloring: T,
    allowed_colors: PartitionBitmap,
    //if set, only consider addrs in this range
    additional_range_filter: Option<(usize, usize)>,
}

impl<T: MemoryColoring + Clone> ColorToPhys<T> {
    pub fn new(
        memory_regions: &'static [MemoryRegion],
        memory_coloring: T,
        allowed_colors: PartitionBitmap,
        additional_range_filter: Option<(usize, usize)>,
    ) -> Self {
        let mut first_usable_region = None;
        let region_contains_start_addr = |mr: &MemoryRegion| match additional_range_filter {
            Some((start_allowed, _)) => {
                mr.start <= (start_allowed as u64) && (start_allowed as u64) < mr.end
            }

            None => true,
        };
        for (mr_idx, mr) in memory_regions.as_ref().iter().enumerate() {
            if mr.kind == MemoryRegionKind::UseableRAM && region_contains_start_addr(mr) {
                first_usable_region = Some(mr_idx);
                break;
            }
        }
        let cur_region_idx = first_usable_region.expect("did not find any usable region");
        let cur_mr = &memory_regions[cur_region_idx];
        let cur_phys_start = cur_mr.start;
        let cur_phys_end = cur_mr.end;
        let cur_range_start = align_up(cur_phys_start, PAGE_SIZE as u64);
        let cur_range_end = align_down(cur_phys_end, PAGE_SIZE as u64);

        Self {
            memory_regions,
            cur_region: Cell::new(CurrentRegion {
                idx: cur_region_idx,
                aligned_end: cur_range_end,
            }),
            inside_cur_region_cursor: Cell::new(cur_range_start as usize),
            memory_coloring: memory_coloring.clone(),
            allowed_colors,
            additional_range_filter,
        }
    }

    //advance internal state to next useable region, returns error if we ran out of regions
    fn advance_to_next_region(&self) -> Result<(), ()> {
        for (mr_idx, mr) in self
            .memory_regions
            .iter()
            .enumerate()
            .skip(self.cur_region.get().idx + 1)
        {
            if mr.kind == MemoryRegionKind::UseableRAM {
                //update reference to current region
                self.cur_region.set(CurrentRegion {
                    idx: mr_idx,
                    aligned_end: align_down(mr.end, PAGE_SIZE as u64),
                });
                //update reference to position inside the region to start of the new region
                let region_start = align_up(mr.start, PAGE_SIZE as u64);
                self.inside_cur_region_cursor.set(region_start as usize);
                return Ok(());
            }
        }
        return Err(());
    }

    //get next frame inside the currently selected region or return None if we hit the end
    //DOES NOT check for color, use `next_frame_in_region_with_color` to ensure that returned frame has allowed color
    fn next_paddr_in_region(&self) -> Option<usize> {
        let cursor = self.inside_cur_region_cursor.get();
        if cursor < self.cur_region.get().aligned_end as usize {
            self.inside_cur_region_cursor.set(cursor + PAGE_SIZE);
            Some(cursor)
        } else {
            None
        }
    }

    //returns the next frame in the current region that has an allowed color or None if the end of the region is reached
    fn next_paddr_in_region_with_color(&self) -> Option<usize> {
        let mut next_paddr = match self.next_paddr_in_region() {
            Some(v) => v,
            None => return None,
        };
        let correct_color = |addr: usize| {
            let paddr_color = self.memory_coloring.compute_color(HostPhysAddr::new(addr));
            self.allowed_colors.get(paddr_color as usize)
        };
        while !correct_color(next_paddr) {
            next_paddr = match self.next_paddr_in_region() {
                Some(v) => v,
                None => return None,
            };
        }
        if correct_color(next_paddr) {
            return Some(next_paddr);
        } else {
            return None;
        }
    }

    fn next_paddr_with_color(&self) -> Option<usize> {
        let mut next_paddr = self.next_paddr_in_region_with_color();
        //if None, advance region and try again until we run out of regions
        let paddr_in_allowed_range = |p| match self.additional_range_filter {
            Some((inc_start, excl_end)) => p >= inc_start && p < excl_end,
            None => true,
        };
        while next_paddr.is_none() || next_paddr.is_some_and(|p| !paddr_in_allowed_range(p)) {
            if self.advance_to_next_region().is_err() {
                return None;
            }
            next_paddr = self.next_paddr_in_region_with_color();
        }

        return next_paddr;
    }

    pub fn visit_all_as_ranges<F: FnMut(PhysRange)>(&self, mut store_cb: F) {
        //normal case: need at least two pages for request
        let first_phy_addr = match self.next_paddr_with_color() {
            Some(v) => v,
            None => return,
        };
        let mut cur_range = PhysRange {
            start: first_phy_addr,
            end: first_phy_addr + PAGE_SIZE,
        };
        /*N.B. we use signed type here as allocations might not be multiple of PAGE_SIZE
        but since we only alloc with PAGE_SIZE granularity, remaining_bytes might become negative in
        the final iteration
        */
        //let mut remaining_bytes: i64 = (size - PAGE_SIZE) as i64;
        //normal case: multiple pages, allocate frames, and group them together if they are contiguous
        while let Some(next_paddr) = self.next_paddr_with_color() {
            if next_paddr == cur_range.end {
                //Case 1: contiguous -> extend cur_range
                cur_range.end = cur_range.end + PAGE_SIZE;
            } else {
                //Case 2: not contiguous, start new range
                //ranges.push(cur_range);
                store_cb(cur_range);
                cur_range = PhysRange {
                    start: next_paddr,
                    end: next_paddr + PAGE_SIZE,
                };
            }
        }
        //store final range before returning
        store_cb(cur_range);
    }
}
