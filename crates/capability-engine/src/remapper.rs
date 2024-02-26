//! Remapper
//!
//! The remapper is not part of the capa-engine, but a wrapper that can be used to keep trap of
//! virtual addresses for platform such as x86 that needs to emulate second-level page tables.

use core::{cmp, fmt};

use crate::region::{MemoryPermission, PermissionIterator};
use crate::{GenArena, Handle, MemOps};

pub struct Remapper<const N: usize> {
    segments: GenArena<Segment, N>,
    head: Option<Handle<Segment>>,
}

/// A mapping from HPA to HPA
pub struct Mapping {
    /// Host Physical Address
    pub hpa: usize,
    /// Guest Physical Address
    pub gpa: usize,
    /// Size of the segment to remap
    pub size: usize,
    /// Number of repetitions
    pub repeat: usize,
    /// Memory permissions
    pub ops: MemOps,
}

#[derive(Clone)]
pub struct Segment {
    /// Host Physical Address
    hpa: usize,
    /// Guest Physical Address
    gpa: usize,
    /// Size of the segment to remap
    size: usize,
    /// Number of repetitions
    repeat: usize,
    /// Next segment in the linked list
    next: Option<Handle<Segment>>,
}

const EMPTY_SEGMENT: Segment = Segment {
    hpa: 0,
    gpa: 0,
    size: 0,
    repeat: 0,
    next: None,
};

impl Segment {
    /// Check if the two segment overlap on the host address space
    #[allow(unused)]
    fn overlap(&self, other: &Segment) -> bool {
        if (other.hpa + other.size) > self.hpa && other.hpa < (self.hpa + other.size) {
            return true;
        }

        false
    }
}

impl<const N: usize> Remapper<N> {
    pub const fn new() -> Self {
        Remapper {
            segments: GenArena::new([EMPTY_SEGMENT; N]),
            head: None,
        }
    }

    pub fn remap<'a>(&'a self, regions: PermissionIterator<'a>) -> RemapIterator<'a, N> {
        RemapIterator {
            regions,
            next_region_start: None,
            segments: self.iter_segments(),
            next_segment_start: None,
            cursor: 0,
            ongoing_segment: None,
            max_segment: None,
        }
    }

    pub fn iter_segments(&self) -> RemapperSegmentIterator<'_, N> {
        RemapperSegmentIterator {
            remapper: self,
            next_segment: self.head,
        }
    }

    pub fn map_range(
        &mut self,
        hpa: usize,
        gpa: usize,
        size: usize,
        repeat: usize,
    ) -> Result<(), ()> {
        let new_segment = self
            .segments
            .allocate(Segment {
                hpa,
                gpa,
                size,
                repeat,
                next: None,
            })
            .ok_or(())?;
        let Some(head) = self.head else {
            // No segment yet, add as the head
            self.head = Some(new_segment);
            return Ok(());
        };

        // Check if the new segment should become the new head
        if hpa < self.segments[head].hpa {
            self.head = Some(new_segment);
            self.segments[new_segment].next = Some(head);
            return Ok(());
        }

        // Iterate segments
        let mut prev = head;
        let mut current = self.segments[head].next;

        while let Some(cursor) = current {
            if hpa < self.segments[cursor].hpa {
                // Let's insert before
                break;
            }

            current = self.segments[cursor].next;
            prev = cursor;
        }

        self.segments[new_segment].next = self.segments[prev].next;
        self.segments[prev].next = Some(new_segment);

        Ok(())
    }

    pub fn unmap_range(&mut self, hpa: usize, size: usize) -> Result<(), ()> {
        let start = hpa;
        let end = hpa + size;

        // Search for segments to unmap
        let mut prev = None;
        let mut cursor = self.head;
        while let Some(cur) = cursor {
            let segment = &self.segments[cur];
            let segment_start = segment.hpa;
            let segment_end = segment.hpa + segment.size;

            // Terminate if there is no more overlap
            if end <= segment_start {
                break;
            }

            // Check for overlaps
            if start < segment_end {
                if start <= segment_start && end >= segment_end {
                    // Complete overlap, remove the segment
                    if let Some(prev) = prev {
                        // Not the head, patch the linked list
                        self.segments[prev].next = self.segments[cur].next;
                    } else {
                        // The segment is the head
                        self.head = self.segments[cur].next;
                    }
                    cursor = self.segments[cur].next;
                    self.segments.free(cur);
                    continue;
                } else if start > segment_start && end < segment_end {
                    // Create a hole in the current segment
                    let new_segment = Segment {
                        hpa: end,
                        gpa: segment.gpa + (end - segment_start),
                        size: segment_end - end,
                        repeat: segment.repeat,
                        next: segment.next,
                    };
                    self.segments[cur].size = start - segment_start;
                    let new_handle = self.segments.allocate(new_segment).ok_or(())?;
                    self.segments[cur].next = Some(new_handle);
                } else if start <= segment_start {
                    // Overlap at the beginning
                    self.segments[cur].hpa = start;
                } else if end >= segment_end {
                    // Overlap at the end
                    self.segments[cur].size = start - segment_start;
                }
            }

            // Or move to next one
            prev = Some(cur);
            cursor = self.segments[cur].next;
        }

        // Couldn't find segment, nothing to do
        Ok(())
    }
}

// ——————————————————————————————— Iterators ———————————————————————————————— //

#[derive(Clone)]
pub struct RemapIterator<'a, const N: usize> {
    regions: PermissionIterator<'a>,
    segments: RemapperSegmentIterator<'a, N>,
    cursor: usize,
    next_region_start: Option<usize>,
    next_segment_start: Option<usize>,
    max_segment: Option<usize>,
    ongoing_segment: Option<SingleSegmentIterator<'a>>,
}

impl<'a, const N: usize> Iterator for RemapIterator<'a, N> {
    type Item = Mapping;

    fn next(&mut self) -> Option<Self::Item> {
        // First, if there is an ongoing segment being remapped, continue
        if let Some(ongoing_segment) = &mut self.ongoing_segment {
            match ongoing_segment.next() {
                Some(mapping) => {
                    return Some(mapping);
                }
                None => {
                    self.ongoing_segment = None;
                }
            }
        }

        // Update next region and segment start, if needed
        if self.next_region_start.is_none() {
            self.next_region_start = self.regions.clone().next().map(|region| region.start);
        }
        if self.next_segment_start.is_none() {
            self.next_segment_start = self.segments.clone().next().map(|segment| segment.hpa);
        }

        match (self.next_segment_start, self.next_region_start) {
            (None, None) => {
                // Nothing more to process
                return None;
            }
            (Some(_), None) => {
                // There are more segments but no more regions
                return None;
            }
            (None, Some(next_region)) => {
                // There are only regions left
                let region = self.regions.next().unwrap();
                let max_segment = self.max_segment.unwrap_or(0);
                self.next_region_start = None;

                // Skip empty regions
                if self.cursor == region.end {
                    return self.next();
                }

                assert!(self.cursor <= next_region);
                assert!(self.cursor < region.end);
                let cursor = cmp::max(self.cursor, region.start);
                self.cursor = region.end;

                if max_segment >= region.end {
                    // Skip this region, already covered
                    return self.next();
                }
                let start = cmp::max(cursor, max_segment);

                let mapping = Mapping {
                    hpa: start,
                    gpa: start,
                    size: region.end - start,
                    repeat: 1,
                    ops: region.ops,
                };
                return Some(mapping);
            }
            (Some(next_segment), Some(next_region)) => {
                assert!(self.cursor <= next_region);
                assert!(self.cursor <= next_segment);

                if next_segment <= next_region {
                    // If a segment comes first, build a segment remapper and retry
                    self.cursor = next_segment;
                    let segment = self.segments.next().unwrap();
                    self.next_segment_start = None;
                    self.max_segment = Some(cmp::max(
                        self.max_segment.unwrap_or(0),
                        segment.hpa + segment.size,
                    ));
                    self.ongoing_segment = Some(SingleSegmentIterator {
                        regions: self.regions.clone(),
                        next_region: None,
                        cursor: self.cursor,
                        segment: segment.clone(),
                    });
                    return self.next();
                } else {
                    // A region comes first, we emit a mapping if no segment covered it
                    let region = self.regions.clone().next().unwrap();
                    let max_segment = self.max_segment.unwrap_or(0);
                    let mapping_end = cmp::min(region.end, next_segment);
                    let cursor = cmp::max(region.start, self.cursor);
                    let cursor = cmp::min(mapping_end, cmp::max(max_segment, cursor));

                    // Move cursor and consume region if needed
                    self.cursor = mapping_end;
                    if mapping_end == region.end {
                        self.next_region_start = None;
                        self.regions.next();
                    } else {
                        self.next_region_start = Some(mapping_end);
                    }

                    if cursor >= max_segment && cursor < mapping_end {
                        // Emit a mapping
                        assert_ne!(cursor, mapping_end);
                        let mapping = Mapping {
                            hpa: cursor,
                            gpa: cursor,
                            size: mapping_end - cursor,
                            repeat: 1,
                            ops: region.ops,
                        };

                        return Some(mapping);
                    } else {
                        // Otherwise move on to next iteration
                        return self.next();
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct SingleSegmentIterator<'a> {
    regions: PermissionIterator<'a>,
    next_region: Option<MemoryPermission>,
    cursor: usize,
    segment: Segment,
}

impl<'a> SingleSegmentIterator<'a> {
    fn next(&mut self) -> Option<Mapping> {
        // Retrieve the current region and segment
        let segment = &self.segment;
        let mut next_region = self.next_region;
        if next_region.is_none() {
            next_region = self.regions.next();
        }
        loop {
            match next_region {
                Some(region) if region.end <= segment.hpa => {
                    // Move to next region
                    next_region = self.regions.next();
                }
                _ => break,
            }
        }
        let Some(region) = next_region else {
            if self.cursor <= segment.hpa + segment.size {
                self.cursor = segment.hpa + segment.size;
            }
            return None;
        };

        // Move cursor
        if self.cursor < segment.hpa {
            self.cursor = segment.hpa;
        }
        if self.cursor < region.start {
            self.cursor = region.start;
        } else if self.cursor == region.end {
            // End of current region: move to the next region and try again
            self.next_region = None;
            return self.next();
        }

        assert!(self.cursor >= region.start);
        assert!(self.cursor < region.start + region.size());
        assert!(self.cursor >= segment.hpa);

        // Check if we reached the end of the segment
        if self.cursor >= segment.hpa + segment.size {
            return None;
        }

        // Otherwise produce the next mapping and update the cursor
        let gpa_offset = self.cursor - segment.hpa;
        let next_cusor = core::cmp::min(segment.hpa + segment.size, region.end);
        let mapping = Mapping {
            hpa: self.cursor,
            gpa: segment.gpa + gpa_offset,
            size: next_cusor - self.cursor,
            repeat: segment.repeat,
            ops: region.ops,
        };
        self.cursor = next_cusor;
        Some(mapping)
    }
}

/// An iterator over the remapper segments.
#[derive(Clone)]
pub struct RemapperSegmentIterator<'a, const N: usize> {
    remapper: &'a Remapper<N>,
    next_segment: Option<Handle<Segment>>,
}

impl<'a, const N: usize> Iterator for RemapperSegmentIterator<'a, N> {
    type Item = &'a Segment;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(next) = self.next_segment {
            let segment = &self.remapper.segments[next];
            self.next_segment = segment.next;
            Some(segment)
        } else {
            None
        }
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NB_TRACKER;
    use crate::debug::snap;
    use crate::region::{TrackerPool, EMPTY_REGION};
    use crate::{RegionTracker, MEMOPS_ALL};

    fn dummy_segment(hpa: usize, gpa: usize, size: usize, repeat: usize) -> Segment {
        Segment {
            hpa,
            gpa,
            size,
            repeat,
            next: None,
        }
    }

    #[test]
    fn overlap() {
        let segment = dummy_segment(20, 0, 10, 1);

        assert!(segment.overlap(&dummy_segment(15, 0, 10, 1)));
        assert!(segment.overlap(&dummy_segment(25, 0, 10, 1)));
        assert!(segment.overlap(&dummy_segment(20, 0, 10, 1)));
        assert!(segment.overlap(&dummy_segment(22, 0, 6, 1)));
        assert!(segment.overlap(&dummy_segment(18, 0, 14, 1)));

        assert!(!segment.overlap(&dummy_segment(10, 0, 5, 1)));
        assert!(!segment.overlap(&dummy_segment(10, 0, 10, 1)));
        assert!(!segment.overlap(&dummy_segment(35, 0, 10, 1)));
        assert!(!segment.overlap(&dummy_segment(30, 0, 10, 1)));
    }

    #[test]
    fn remap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();

        // Add a first region
        tracker
            .add_region(0x10, 0x20, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x10, 0x20 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        snap(
            "{[0x10, 0x20 at 0x10, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        // Remap that region
        remapper.map_range(0x10, 0x110, 0x10, 1).unwrap();
        snap(
            "{[0x10, 0x20 at 0x110, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        // Let's add a few more!
        tracker
            .add_region(0x30, 0x40, MEMOPS_ALL, &mut pool)
            .unwrap();
        tracker
            .add_region(0x40, 0x50, MemOps::READ, &mut pool)
            .unwrap();
        snap("{[0x10, 0x20 | 1 (1 - 1 - 1 - 1)] -> [0x30, 0x40 | 1 (1 - 1 - 1 - 1)] -> [0x40, 0x50 | 1 (1 - 0 - 0 - 0)]}", &tracker.iter(&pool));
        snap(
            "{[0x10, 0x20 at 0x110, rep 1 | RWXS] -> [0x30, 0x40 at 0x30, rep 1 | RWXS] -> [0x40, 0x50 at 0x40, rep 1 | R___]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        // And (partially) remap those
        remapper.map_range(0x30, 0x130, 0x8, 1).unwrap();
        snap(
            "{[0x10, 0x20 at 0x110, rep 1 | RWXS] -> [0x30, 0x38 at 0x130, rep 1 | RWXS] -> [0x38, 0x40 at 0x38, rep 1 | RWXS] -> [0x40, 0x50 at 0x40, rep 1 | R___]}",
            &remapper.remap(tracker.permissions(&pool)),
        );
        remapper.map_range(0x38, 0x238, 0x8, 1).unwrap();
        snap(
            "{[0x10, 0x20 at 0x110, rep 1 | RWXS] -> [0x30, 0x38 at 0x130, rep 1 | RWXS] -> [0x38, 0x40 at 0x238, rep 1 | RWXS] -> [0x40, 0x50 at 0x40, rep 1 | R___]}",
            &remapper.remap(tracker.permissions(&pool)),
        );
        remapper.map_range(0x40, 0x140, 0x10, 3).unwrap();
        snap(
            "{[0x10, 0x20 at 0x110, rep 1 | RWXS] -> [0x30, 0x38 at 0x130, rep 1 | RWXS] -> [0x38, 0x40 at 0x238, rep 1 | RWXS] -> [0x40, 0x50 at 0x140, rep 3 | R___]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        // Unmap some segments
        remapper.unmap_range(0x38, 0x8).unwrap();
        snap(
            "{[0x10, 0x20 at 0x110, rep 1 | RWXS] -> [0x30, 0x38 at 0x130, rep 1 | RWXS] -> [0x38, 0x40 at 0x38, rep 1 | RWXS] -> [0x40, 0x50 at 0x140, rep 3 | R___]}",
            &remapper.remap(tracker.permissions(&pool)),
        );
        remapper.unmap_range(0x30, 0x8).unwrap();
        snap(
            "{[0x10, 0x20 at 0x110, rep 1 | RWXS] -> [0x30, 0x40 at 0x30, rep 1 | RWXS] -> [0x40, 0x50 at 0x140, rep 3 | R___]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        // Delete regions but not the segments yet
        tracker
            .remove_region(0x40, 0x50, MemOps::READ, &mut pool)
            .unwrap();
        snap(
            "{[0x10, 0x20 | 1 (1 - 1 - 1 - 1)] -> [0x30, 0x40 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );
        snap(
            "{[0x10, 0x20 at 0x110, rep 1 | RWXS] -> [0x30, 0x40 at 0x30, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        // Unmap more segments
        remapper.unmap_range(0x40, 0x10).unwrap();
        snap(
            "{[0x10, 0x20 at 0x110, rep 1 | RWXS] -> [0x30, 0x40 at 0x30, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );
        remapper.unmap_range(0x10, 0x10).unwrap();
        snap(
            "{[0x10, 0x20 at 0x10, rep 1 | RWXS] -> [0x30, 0x40 at 0x30, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );
    }

    #[test]
    fn cross_regions() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();

        // Add two regions with hole
        tracker
            .add_region(0x10, 0x30, MEMOPS_ALL, &mut pool)
            .unwrap();
        tracker
            .add_region(0x40, 0x60, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap(
            "{[0x10, 0x30 | 1 (1 - 1 - 1 - 1)] -> [0x40, 0x60 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );
        snap(
            "{[0x10, 0x30 at 0x10, rep 1 | RWXS] -> [0x40, 0x60 at 0x40, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        // Create a mapping that cross the region boundary
        remapper.map_range(0x20, 0x100, 0x100, 1).unwrap();
        snap(
            "{[0x10, 0x20 at 0x10, rep 1 | RWXS] -> [0x20, 0x30 at 0x100, rep 1 | RWXS] -> [0x40, 0x60 at 0x120, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );
    }

    #[test]
    fn backward_overlap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();

        tracker
            .add_region(0x10, 0x40, MEMOPS_ALL, &mut pool)
            .unwrap();
        tracker
            .add_region(0x30, 0x40, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap(
            "{[0x10, 0x30 | 1 (1 - 1 - 1 - 1)] -> [0x30, 0x40 | 2 (2 - 2 - 2 - 2)]}",
            &tracker.iter(&pool),
        );

        remapper.map_range(0x10, 0x100, 0x30, 1).unwrap();
        remapper.map_range(0x30, 0x50, 0x10, 1).unwrap();
        snap(
            "{[0x10, 0x40 at 0x100, rep 1] -> [0x30, 0x40 at 0x50, rep 1]}",
            remapper.iter_segments(),
        );
        snap(
            // Note: here for some reason the tracker do not properly merge the two contiguous
            // regions. We should figure that out at some point and optimize the tracker.
            "{[0x10, 0x30 at 0x100, rep 1 | RWXS] -> [0x30, 0x40 at 0x120, rep 1 | RWXS] -> [0x30, 0x40 at 0x50, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );
    }

    #[test]
    fn forward_overlap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();

        tracker
            .add_region(0x10, 0x40, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x10, 0x40 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));

        remapper.map_range(0x20, 0x100, 0x10, 1).unwrap();
        remapper.map_range(0x30, 0x200, 0x10, 1).unwrap();
        snap(
            "{[0x10, 0x20 at 0x10, rep 1 | RWXS] -> [0x20, 0x30 at 0x100, rep 1 | RWXS] -> [0x30, 0x40 at 0x200, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        remapper.map_range(0x10, 0x300, 0x30, 1).unwrap();
        snap(
            "{[0x10, 0x40 at 0x300, rep 1 | RWXS] -> [0x20, 0x30 at 0x100, rep 1 | RWXS] -> [0x30, 0x40 at 0x200, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );
    }

    #[test]
    fn update_region() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();

        // Add one region
        tracker
            .add_region(0x10, 0x60, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x10, 0x60 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        snap(
            "{[0x10, 0x60 at 0x10, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        // Remap the whole region
        remapper.map_range(0x10, 0x100, 0x50, 1).unwrap();
        snap(
            "{[0x10, 0x60 at 0x100, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );

        // Split the region in two
        tracker
            .remove_region(0x10, 0x60, MEMOPS_ALL, &mut pool)
            .unwrap();
        tracker
            .add_region(0x10, 0x20, MEMOPS_ALL, &mut pool)
            .unwrap();
        tracker
            .add_region(0x20, 0x40, MEMOPS_ALL, &mut pool)
            .unwrap();
        tracker
            .add_region(0x40, 0x60, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x10, 0x60 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        snap(
            "{[0x10, 0x60 at 0x100, rep 1 | RWXS]}",
            &remapper.remap(tracker.permissions(&pool)),
        );
    }

    #[test]
    fn split_region() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();

        tracker
            .add_region(0x12fcb6000, 0x12fcf6000, MEMOPS_ALL, &mut pool)
            .unwrap();
        remapper
            .map_range(0x12fcb6000, 0xfffc0000, 0x40000, 1)
            .unwrap();
        tracker
            .add_region(0x12fcd6000, 0x12fcf6000, MEMOPS_ALL, &mut pool)
            .unwrap();
        remapper
            .map_range(0x12fcd6000, 0xe0000, 0x20000, 1)
            .unwrap();
        snap("{[0x12fcb6000, 0x12fcd6000 | 1 (1 - 1 - 1 - 1)] -> [0x12fcd6000, 0x12fcf6000 | 2 (2 - 2 - 2 - 2)]}", &tracker.iter(&pool));
        snap("{[0x12fcb6000, 0x12fcf6000 at 0xfffc0000, rep 1] -> [0x12fcd6000, 0x12fcf6000 at 0xe0000, rep 1]}", remapper.iter_segments());
    }

    #[test]
    fn debug_iterator() {
        let mut remapper: Remapper<32> = Remapper::new();

        remapper.map_range(0x10, 0x100, 0x20, 2).unwrap();
        snap("{[0x10, 0x30 at 0x100, rep 2]}", &remapper.iter_segments());
        remapper.map_range(0x30, 0x200, 0x20, 1).unwrap();
        snap(
            "{[0x10, 0x30 at 0x100, rep 2] -> [0x30, 0x50 at 0x200, rep 1]}",
            &remapper.iter_segments(),
        );
        remapper.map_range(0x80, 0x100, 0x20, 1).unwrap();
        snap("{[0x10, 0x30 at 0x100, rep 2] -> [0x30, 0x50 at 0x200, rep 1] -> [0x80, 0xa0 at 0x100, rep 1]}", &remapper.iter_segments());
    }

    #[test]
    fn single_segment_iterator() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();

        // Create a single region
        tracker
            .add_region(0x30, 0x60, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x30, 0x60 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x10, 0x100, 0x10, 1),
        };
        snap("", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x70, 0x100, 0x10, 1),
        };
        snap("", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x20, 0x100, 0x20, 1),
        };
        snap("[0x30, 0x40 at 0x110, rep 1 | RWXS]", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x50, 0x100, 0x20, 1),
        };
        snap("[0x50, 0x60 at 0x100, rep 1 | RWXS]", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x40, 0x100, 0x10, 1),
        };
        snap("[0x40, 0x50 at 0x100, rep 1 | RWXS]", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x20, 0x100, 0x50, 1),
        };
        snap("[0x30, 0x60 at 0x110, rep 1 | RWXS]", iterator);

        // Let's experiment with multiple regions now
        tracker
            .add_region(0x70, 0x80, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap(
            "{[0x30, 0x60 | 1 (1 - 1 - 1 - 1)] -> [0x70, 0x80 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x20, 0x100, 0x80, 1),
        };
        snap(
            "[0x30, 0x60 at 0x110, rep 1 | RWXS] -> [0x70, 0x80 at 0x150, rep 1 | RWXS]",
            iterator,
        );
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl fmt::Display for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[0x{:x}, 0x{:x} at 0x{:x}, rep {} | {}]",
            self.hpa,
            self.hpa + self.size,
            self.gpa,
            self.repeat,
            self.ops,
        )
    }
}

impl<'a, const N: usize> fmt::Display for RemapIterator<'a, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        write!(f, "{{")?;
        for mapping in self.clone() {
            if first {
                first = false;
            } else {
                write!(f, " -> ")?;
            }
            write!(f, "{}", mapping,)?;
        }
        write!(f, "}}")
    }
}

impl<'a, const N: usize> fmt::Display for RemapperSegmentIterator<'a, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        write!(f, "{{")?;
        for segment in self.clone() {
            if first {
                first = false;
            } else {
                write!(f, " -> ")?;
            }
            write!(
                f,
                "[0x{:x}, 0x{:x} at 0x{:x}, rep {}]",
                segment.hpa,
                segment.hpa + segment.size,
                segment.gpa,
                segment.repeat,
            )?;
        }
        write!(f, "}}")
    }
}

impl<'a> fmt::Display for SingleSegmentIterator<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut iter = self.clone();
        loop {
            let next = iter.next();
            let mapping = match next {
                Some(mapping) => mapping,
                None => {
                    return Ok(());
                }
            };
            if first {
                first = false;
            } else {
                write!(f, " -> ")?;
            }
            write!(
                f,
                "[0x{:x}, 0x{:x} at 0x{:x}, rep {} | {}]",
                mapping.hpa,
                mapping.hpa + mapping.size,
                mapping.gpa,
                mapping.repeat,
                mapping.ops,
            )?;
        }
    }
}
