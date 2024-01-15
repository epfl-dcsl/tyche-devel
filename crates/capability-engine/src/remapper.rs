//! Remapper
//!
//! The remapper is not part of the capa-engine, but a wrapper that can be used to keep trap of
//! virtual addresses for platform such as x86 that needs to emulate secon-level page tables.

use core::fmt;

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

struct Segment {
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
            next_region: None,
            remapper: self,
            next_segment: self.head,
            cursor: 0,
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
            if self.segments[new_segment].overlap(&self.segments[head]) {
                return Err(()); // No overlap allowed for now
            }

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
        let Some(head) = self.head else {
            return Err(());
        };

        // Check if unmapping the head
        let head_segment = &self.segments[head];
        if head_segment.hpa == hpa {
            assert_eq!(
                head_segment.size, size,
                "For now we require unmap to match a mapped range"
            );
            self.head = head_segment.next;
            self.segments.free(head);
            return Ok(());
        }

        // Search for the segment to unmap
        let mut prev = head;
        let mut cursor = head_segment.next;
        while let Some(cur) = cursor {
            let segment = &self.segments[cur];

            // Remove segment
            if segment.hpa == hpa {
                assert_eq!(
                    segment.size, size,
                    "For now we require unmap to match a mapped range"
                );
                let next = segment.next;
                self.segments[prev].next = next;
                self.segments.free(cur);
                return Ok(());
            }

            // Or move to next one
            prev = cur;
            cursor = segment.next;
        }

        // Couldn't find segment
        Err(())
    }
}

// ——————————————————————————————— Iterators ———————————————————————————————— //

#[derive(Clone)]
pub struct RemapIterator<'a, const N: usize> {
    regions: PermissionIterator<'a>,
    next_region: Option<MemoryPermission>,
    remapper: &'a Remapper<N>,
    next_segment: Option<Handle<Segment>>,
    cursor: usize,
}

impl<'a, const N: usize> Iterator for RemapIterator<'a, N> {
    type Item = Mapping;

    fn next(&mut self) -> Option<Self::Item> {
        // Retrieve the current region
        let region = match self.next_region {
            Some(region) => region,
            None => {
                if let Some(region) = self.regions.next() {
                    // Move to next region
                    self.next_region = Some(region);
                    region
                } else {
                    // No more region to process
                    return None;
                }
            }
        };

        // Move cursor
        if self.cursor < region.start {
            self.cursor = region.start;
        } else if self.cursor == region.end {
            // End of current region: move to the next region and try again
            self.next_region = None;
            return self.next();
        }
        assert!(self.cursor >= region.start);
        assert!(self.cursor < region.start + region.size());

        // Move to next segment, if any
        while let Some(segment) = self.next_segment {
            let segment = &self.remapper.segments[segment];
            if segment.hpa < self.cursor {
                self.next_segment = segment.next;
            } else {
                break;
            }
        }

        match self.next_segment {
            Some(segment) if self.remapper.segments[segment].hpa == self.cursor => {
                // We found a segment!
                let segment = &self.remapper.segments[segment];
                assert!(segment.hpa + segment.size <= region.end); // Segments can't cross regions
                let mapping = Mapping {
                    hpa: segment.hpa,
                    gpa: segment.gpa,
                    size: segment.size,
                    repeat: segment.repeat,
                    ops: region.ops,
                };
                self.cursor += segment.size;
                Some(mapping)
            }
            _ => {
                // No remapping for this regions
                let end = if let Some(segment) = self.next_segment {
                    let segment_start = self.remapper.segments[segment].hpa;
                    core::cmp::min(region.end, segment_start)
                } else {
                    region.end
                };
                let hpa = self.cursor;
                let size = end - hpa;
                self.cursor = end;
                Some(Mapping {
                    hpa,
                    gpa: hpa,
                    size,
                    repeat: 1,
                    ops: region.ops,
                })
            }
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
}

// ———————————————————————————————— Display ————————————————————————————————— //

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
        write!(f, "}}")
    }
}
