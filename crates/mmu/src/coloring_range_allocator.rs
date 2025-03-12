use core::cell::{RefCell, RefMut};

use crate::frame_allocator::PhysRange;
use crate::ioptmapper::PAGE_SIZE;
use crate::memory_painter::{MemoryRegion, MemoryRegionKind};
use crate::{FrameAllocator, RangeAllocator};

extern crate alloc;
use alloc::vec::Vec;

use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};

/// Range allocator that only returns phys contig ranges with the same color
pub struct ColoringRangeFrameAllocator {
    // pre computed pyhs ranges matching the colors of this allocator
    ranges: RefCell<Vec<PhysRange>>,
    phys_to_virt_offset: HostVirtAddr,
    //info for computing GPAs used by stage2
    memory_regions: Vec<MemoryRegion>,
    mr_idx: RefCell<usize>,
    gpa_of_next_allocation: RefCell<u64>,
}

impl ColoringRangeFrameAllocator {
    pub fn new(
        color_to_phys: &Vec<Vec<PhysRange>>,
        first_color: u64,
        color_count: u64,
        phys_to_virt_offset: HostVirtAddr,
        memory_regions: Vec<MemoryRegion>,
    ) -> Self {
        let mut ranges_vec: Vec<PhysRange> = Vec::new();
        for color_mrs in &color_to_phys[first_color as usize..(first_color + color_count) as usize]
        {
            ranges_vec.append(&mut color_mrs.clone());
        }
        //ensure that lowest address is at the back.
        // This way we can pop elemens from he back while we allocate and still return
        // the memory from low, to high
        ranges_vec.sort_unstable();
        ranges_vec.reverse();
        let mut merged_vec = Vec::new();
        let mut cur = ranges_vec[0];
        //N.B. that memory ranges of different colors cannot overlap
        for (idx, r) in ranges_vec.iter().enumerate().skip(1) {
            if cur.end == r.start {
                cur.end = r.end
            } else {
                merged_vec.push(cur);
                cur = *r;
            }
            if idx == ranges_vec.len() - 1 {
                merged_vec.push(cur);
            }
        }

        let mr_idx;
        let gpa_of_next_allocation;
        if memory_regions[0].kind != MemoryRegionKind::UseableRAM {
            mr_idx = RefCell::new(1);
            gpa_of_next_allocation = RefCell::new(memory_regions[0].end);
        } else {
            mr_idx = RefCell::new(0);
            gpa_of_next_allocation = RefCell::new(0);
        }

        Self {
            ranges: RefCell::new(merged_vec),
            phys_to_virt_offset,
            memory_regions,
            mr_idx,
            gpa_of_next_allocation,
        }
    }

    //call this whenever we might have switched to a new memory region, i.e. after moving from one phys range to another
    // this will update gpa_of_next_allocation accordingly
    fn update_region(&self, ranges: &RefMut<Vec<PhysRange>>) {
        let cur_mr_idx = *self.mr_idx.borrow();
        let cur_mr = self.memory_regions[cur_mr_idx];
        let lowest_hpa = match ranges.last() {
            Some(v) => v.start.as_u64(),
            None => return,
        };

        // still in same region
        if lowest_hpa >= cur_mr.start && lowest_hpa < cur_mr.end {
            return;
        }

        //find new region and update next gpa accordingly

        let mut prev_region = self.memory_regions[cur_mr_idx];
        for (mr_idx, mr) in self.memory_regions.iter().enumerate().skip(cur_mr_idx + 1) {
            if prev_region.end < mr.start {
                let gap_size = mr.start - prev_region.end;
                assert_eq!(
                    gap_size % (PAGE_SIZE as u64),
                    0,
                    "gap between regions is not a multiple of page size"
                );

                self.gpa_of_next_allocation
                    .replace_with(|old| *old + gap_size);
            }
            //fallthrough is intended. We can have a gap and then the next region could also be not useable
            match mr.kind {
                MemoryRegionKind::UseableRAM => {
                    if lowest_hpa >= mr.start && lowest_hpa < mr.end {
                        //Found region that corresponds to our range
                        self.mr_idx.replace(mr_idx);
                        break;
                    }
                }
                MemoryRegionKind::Reserved => {
                    let size = mr.end - mr.start;
                    self.gpa_of_next_allocation.replace_with(|old| *old + size);
                    assert_eq!(size % (PAGE_SIZE as u64), 0, "region is not page aligned");
                }
            }
            prev_region = *mr;
        }
    }
}

unsafe impl FrameAllocator for ColoringRangeFrameAllocator {
    fn allocate_frame(&self) -> Option<vmx::Frame> {
        if self.ranges.borrow().len() == 0 {
            return None;
        }

        let mut ranges = self.ranges.borrow_mut();
        let len = ranges.len();
        let range = &mut ranges[len - 1];
        assert!(range.start + PAGE_SIZE <= range.end, "Unexpected range len");

        let virt = HostVirtAddr::new(range.start.as_usize() + self.phys_to_virt_offset.as_usize());
        let frame = unsafe { vmx::Frame::new(range.start, virt) };

        range.start = range.start + PAGE_SIZE;
        if range.start == range.end {
            ranges.pop();
            self.update_region(&ranges);
        }

        self.gpa_of_next_allocation
            .replace_with(|old| *old + PAGE_SIZE as u64);
        return Some(frame);
    }

    fn get_physical_offset(&self) -> vmx::HostVirtAddr {
        self.phys_to_virt_offset
    }
}

unsafe impl RangeAllocator for ColoringRangeFrameAllocator {
    fn allocate_range<F: FnMut(PhysRange)>(&self, size: usize, mut store_cb: F) -> Result<(), ()> {
        //edge case: at most one page requested
        if size <= PAGE_SIZE {
            let frame = match self.allocate_frame() {
                Some(v) => v,
                None => return Err(()),
            };
            store_cb(PhysRange {
                start: frame.phys_addr,
                end: frame.phys_addr + PAGE_SIZE,
            });
            return Ok(());
        }

        let mut ranges = self.ranges.borrow_mut();

        let mut remaining_bytes = size;
        //normal case: multiple pages, allocate frames, and group them together if they are contiguous
        while remaining_bytes > 0 {
            let range = match ranges.last() {
                Some(r) => *r,
                None => return Err(()),
            };
            if range.size() < remaining_bytes {
                //Consume whole range

                self.gpa_of_next_allocation
                    .replace_with(|old| *old + (range.size() as u64));
                ranges.pop();
                self.update_region(&ranges);

                store_cb(range.clone());
                remaining_bytes -= range.size();
            } else {
                //Use only part of range but round to page boundaries, even that could mean wasting some memory
                let divider =
                    HostPhysAddr::new(range.start.as_usize() + remaining_bytes).align_up(4096);
                let allocated_range = PhysRange {
                    start: range.start,
                    end: divider,
                };
                self.gpa_of_next_allocation
                    .replace_with(|old| *old + (allocated_range.size() as u64));
                store_cb(allocated_range);

                let updated_start = divider;
                let updated_end = range.end;
                let updated_range = PhysRange {
                    start: updated_start,
                    end: updated_end,
                };
                *ranges.last_mut().unwrap() = updated_range;
                remaining_bytes = 0;
            }
        }

        Ok(())
    }

    fn gpa_of_next_allocation(&self) -> GuestPhysAddr {
        self.update_region(&self.ranges.borrow_mut());
        GuestPhysAddr::new(*self.gpa_of_next_allocation.borrow() as usize)
    }
}
