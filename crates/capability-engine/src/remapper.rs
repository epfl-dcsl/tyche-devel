//! Remapper
//!
//! The remapper is not part of the capa-engine, but a wrapper that can be used to keep trap of
//! virtual addresses for platform such as x86 that needs to emulate second-level page tables.

use core::arch::asm;
use core::iter::Peekable;
use core::{array, cmp, fmt, mem};

use kmerge_iter::{new_compactified_mapping_iter, CompatifiedMappingIter, MergedRemapIter};
use mmu::ioptmapper::PAGE_SIZE;
use mmu::memory_coloring::{MemoryColoring, PartitionBitmap};
use utils::{GuestPhysAddr, HostPhysAddr};

use crate::config::NB_TRACKER;
use crate::region::{
    MemoryPermission, PermissionIterator, RegionResourceKind, TrackerPool, EMPTY_REGION,
};
use crate::{CapaError, GenArena, Handle, MemOps, RegionIterator, RegionTracker, ResourceKind};

mod kmerge_iter;

pub struct Remapper<const SIMPLE: usize, const COMPACT: usize> {
    //simple remappings
    segments: GenArena<Segment, SIMPLE>,
    //complex, compactifier remappings
    compact_remaps: GenArena<CompactRemap, COMPACT>,
    // Linked list to traverse segments in sorted order
    segments_head: Option<Handle<Segment>>,
    //store regions referenced by CompactRemap here
    remapper_region_pool: TrackerPool,
}

#[derive(Clone, Copy)]
pub struct CompactRemap {
    color_range: (usize, usize),
    include_devices: bool,
    start_gpa: usize,
    regions: RegionTracker,
}

impl CompactRemap {
    const fn empty() -> Self {
        Self {
            color_range: (0, 0),
            include_devices: false,
            start_gpa: 0,
            regions: RegionTracker::new(),
        }
    }
}

/// A mapping from HPA to HPA
#[derive(Debug, Clone, Copy)]
pub struct Mapping {
    /// Host Physical Address
    pub hpa: usize,
    /// Guest Physical Address
    pub gpa: usize,
    /// Size of the segment to remap
    pub size: usize,
    /// Number of repetitions
    pub repeat: usize,
    /// Memory ptracker.permissions
    pub ops: MemOps,
    /// Additional dimension of access rights that describe how this should get mapped
    /// Adds supports for resource exlusivity
    pub resource_kind: ResourceKind,
}

///
#[derive(Clone, Debug, Copy)]
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
impl<const SIMPLE: usize, const COMPACT: usize> Remapper<SIMPLE, COMPACT> {
    pub const fn new() -> Self {
        let v = Remapper {
            segments: GenArena::new([EMPTY_SEGMENT; SIMPLE]),
            segments_head: None,
            compact_remaps: GenArena::new([CompactRemap::empty(); COMPACT]),
            remapper_region_pool: TrackerPool::new([EMPTY_REGION; NB_TRACKER]),
        };
        v
    }

    pub fn new_merged_remap_iter<'a, T>(
        &'a self,
        coloring: T,
    ) -> MergedRemapIter<'a, SIMPLE, COMPACT, T>
    where
        T: MemoryColoring + Clone + Default,
    {
        let simple = &self.segments;

        let mut compactified_iters: [CompatifiedMappingIter<'a, T>; COMPACT] =
            array::from_fn(|_| CompatifiedMappingIter::default());
        let mut compactified_len = 0;
        for handle in &self.compact_remaps {
            let cr = self
                .compact_remaps
                .get(handle)
                .expect("failed to get cmapct remap from pool");
            let bm = PartitionBitmap::try_from(cr.color_range).expect("malformed color range");

            let perm_iter = cr.regions.permissions(
                &self.remapper_region_pool,
                coloring.clone(),
                Some(bm),
                cr.include_devices,
            );

            assert!(compactified_len < compactified_iters.len());
            compactified_iters[compactified_len] =
                new_compactified_mapping_iter(perm_iter, cr.start_gpa);
            compactified_len += 1;
        }
        MergedRemapIter::new(
            self.iter_segments().peekable(),
            compactified_iters,
            compactified_len,
        )
    }

    pub fn new_remap_iter<'a, T: MemoryColoring + Clone + Default>(
        &'a self,
        coloring: T,
        regions: PermissionIterator<'a, T>,
    ) -> RemapIterator<'a, SIMPLE, COMPACT, T> {
        let merged_remap_iter: MergedRemapIter<SIMPLE, COMPACT, T> =
            self.new_merged_remap_iter(coloring);
        RemapIterator {
            regions: regions.peekable(),
            next_region_start: None,
            remap_commands_iter: merged_remap_iter.peekable(),
            next_segment_start: None,
            cursor: 0,
            ongoing_segment: None,
            max_segment: None,
        }
    }

    pub fn iter_segments(&self) -> RemapperSegmentIterator<'_, SIMPLE, COMPACT> {
        RemapperSegmentIterator {
            remapper: self,
            next_segment: self.segments_head,
        }
    }

    ///
    /// # Arguments
    /// - `color_range` : start inclusive, end exclusive
    pub fn map_compactified_range(
        &mut self,
        color_range: (usize, usize),
        include_devices: bool,
        start_gpa: usize,
        regions_iter: RegionIterator,
    ) -> Result<(), CapaError> {
        let mut remap_region_snapshot = RegionTracker::new();
        for (a, x) in regions_iter {
            let is_device = match x.get_resource_kind() {
                RegionResourceKind::Device => true,
                _ => false,
            };
            if is_device && !include_devices {
                continue;
            }
            remap_region_snapshot
                .add_region(
                    x.get_start(),
                    x.get_end(),
                    x.get_ops(),
                    ResourceKind::from(&x.get_resource_kind()),
                    &mut self.remapper_region_pool,
                )
                .expect("remapper::map_compactified_range failed to add region");
        }
        let entry: CompactRemap = CompactRemap {
            start_gpa,
            color_range,
            include_devices,
            regions: remap_region_snapshot,
        };

        //TODO: sanity check that this does not overlap with any existing stuff:

        let _handle = self
            .compact_remaps
            .allocate(entry)
            .ok_or(CapaError::OutOfMemory)?;

        Ok(())
    }

    pub fn map_range(
        &mut self,
        hpa: usize,
        gpa: usize,
        size: usize,
        repeat: usize,
    ) -> Result<(), CapaError> {
        if self.overlaps(gpa, size * repeat) {
            return Err(CapaError::AlreadyAliased);
        }
        Ok(self
            .insert_segment(Segment {
                hpa,
                gpa,
                size,
                repeat,
                next: None,
            }).map_err(|e| {
                log::error!("Remapper:map_range: failed to insert segment hpa 0x{:013x}, gpa 0x{:013x} size 0x{:x}, repeat {} : {:?}",
            hpa,gpa, size,repeat,e);
            CapaError::InternalMappingError
            })?)
    }

    pub fn unmap_range(&mut self, hpa: usize, size: usize) -> Result<(), ()> {
        let start = hpa;
        let end = hpa + size;

        // Search for segments to unmap
        let mut prev = None;
        let mut cursor = self.segments_head;
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
                        self.segments_head = self.segments[cur].next;
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

    pub fn unmap_gpa_range(&mut self, gpa: usize, size: usize) -> Result<(), ()> {
        let Some(head) = self.segments_head else {
            // No segment yet, nothing to do
            return Ok(());
        };
        if size == 0 {
            // Nothing to do
            return Ok(());
        }

        let end = gpa + size;
        let mut cursor = head;
        let mut prev: Option<Handle<Segment>> = None;
        let mut next;
        loop {
            let current = &mut self.segments[cursor];
            let curr_gpa = current.gpa;
            let curr_end = curr_gpa + current.size * current.repeat;
            next = current.next;

            // Intersect the current gpa at the start.
            if gpa <= curr_gpa && end > curr_gpa {
                // Do we cover the entire segment?
                if end >= curr_end {
                    // We can remove the entire segment.
                    if let Some(prev) = prev {
                        let prev = &mut self.segments[prev];
                        prev.next = next;
                    } else {
                        // This was the head.
                        self.segments_head = next;
                    }
                    // Delete the segment.
                    self.segments.free(cursor);

                    // Update the loop, do not change the prev.
                    if let Some(next) = next {
                        cursor = next;
                        continue;
                    } else {
                        return Ok(());
                    }
                } else {
                    // This is a partial overlap, we update the mapping.
                    assert!(current.repeat == 1, "Repeat not yet supported");
                    let offset = end - curr_gpa;
                    current.gpa = end;
                    current.hpa = current.hpa + offset;
                    current.size = current.size - offset;
                }
            } else if gpa > curr_gpa && gpa < curr_end {
                // Intersects at the middle or the end.
                assert!(current.repeat == 1, "Repeat not yet supported");
                // We need to shorten the segment.
                let offset = end - curr_gpa;
                current.size = gpa - curr_gpa;
                // We will have to create a new segment.
                if end < curr_end {
                    let new_segment = Segment {
                        hpa: current.hpa + offset,
                        gpa: end,
                        size: curr_end - end,
                        repeat: current.repeat,
                        next: None,
                    };
                    self.insert_segment(new_segment)?;
                }
            }
            // Keep a pointer to the prev.
            prev = Some(cursor);
            if let Some(next) = next {
                cursor = next;
            } else {
                return Ok(());
            }
        }
    }

    pub fn overlaps(&self, start: usize, size: usize) -> bool {
        let end = start + size;
        for s in self.iter_segments() {
            let segment_end = s.gpa + s.size * s.repeat;
            if (s.gpa <= start && start < segment_end) || (s.gpa < end && end <= segment_end) {
                return true;
            }
            // Quick escape assuming everything is correctly sorted.
            if s.gpa > end {
                return false;
            }
        }
        return false;
    }

    fn insert_segment(&mut self, segment: Segment) -> Result<(), ()> {
        let hpa = segment.hpa;
        let new_segment = self.segments.allocate(segment).ok_or_else(|| {
            log::error!("insert_segment: failed to allocate new segment. Out of memory?");
            ()
        })?;
        let Some(head) = self.segments_head else {
            // No segment yet, add as the head
            self.segments_head = Some(new_segment);
            return Ok(());
        };

        // Check if the new segment should become the new head
        if hpa < self.segments[head].hpa {
            self.segments_head = Some(new_segment);
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
}

// ——————————————————————————————— Iterators ———————————————————————————————— //

#[derive(Clone)]
pub struct RemapIterator<
    'a,
    const SIMPLE: usize,
    const COMPACT: usize,
    T: MemoryColoring + Clone + Default,
> {
    //luca: deduplicated view of the memory ptracker.permissions for our domain
    regions: Peekable<PermissionIterator<'a, T>>,
    //luca: just simple iterator over existing segments
    remap_commands_iter: Peekable<MergedRemapIter<'a, SIMPLE, COMPACT, T>>,
    cursor: usize,
    next_region_start: Option<usize>,
    next_segment_start: Option<usize>,
    max_segment: Option<usize>,
    ongoing_segment: Option<SingleSegmentIterator<'a, T>>,
}

impl<'a, const SIMPLE: usize, const COMPACT: usize, T: MemoryColoring + Clone + Default> Iterator
    for RemapIterator<'a, SIMPLE, COMPACT, T>
{
    type Item = Mapping;

    /*Initial state
       pub fn new_remap_iter<'a, T: MemoryColoring + Clone + Default>(
        &'a self,
        coloring: T,
        regions: PermissionIterator<'a, T>,
    ) -> RemapIterator<'a, SIMPLE, COMPACT, T> {
        let merged_remap_iter: MergedRemapIter<SIMPLE, COMPACT, T> =
            self.new_merged_remap_iter(coloring);
        RemapIterator {
            regions,
            next_region_start: None,
            remap_commands_iter: merged_remap_iter,
            next_segment_start: None,
            cursor: 0,
            ongoing_segment: None,
            max_segment: None,
        }
    }
    */
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // First, if there is an ongoing segment being remapped, continue
            if let Some(ongoing_segment) = &mut self.ongoing_segment {
                //luca: this will match the segment to the regions to create a mapping object
                //The matching to region is required to figure out the ptracker.permissions
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
                //luca: we do clone+next as a way to get a peek without changing the state
                self.next_region_start = self.regions.peek().map(|region| region.start);
            }
            if self.next_segment_start.is_none() {
                self.next_segment_start =
                    self.remap_commands_iter.peek().map(|segment| segment.hpa);
            }

            //luca: Terminology:
            // - Segment: chunck of contig mem that we want to map
            // - region: phys mem that we have access to
            match (self.next_segment_start, self.next_region_start) {
                (None, None) => {
                    // Nothing more to process
                    return None;
                }
                (Some(_), None) => {
                    // There are more segments but no more regions
                    //luca: I guess this shoudl not happen, it basically means that
                    //some of our remapping requests do not match the available physical mem
                    return None;
                }
                (None, Some(next_region)) => {
                    // There are only regions left
                    //luca: we identity map all of this, as we don't have any segments/remappings

                    let region = self.regions.next().unwrap();
                    //luca: largest start addr of a segment?
                    let max_segment = self.max_segment.unwrap_or(0);
                    self.next_region_start = None;

                    // Skip empty regions
                    if self.cursor == region.end {
                        //luca:: recursion!!!, that looks dangerous
                        //return self.next();
                        continue;
                    }

                    assert!(self.cursor <= next_region);
                    assert!(self.cursor < region.end);
                    let cursor = cmp::max(self.cursor, region.start);
                    self.cursor = region.end;

                    if max_segment >= region.end {
                        // Skip this region, already covered
                        //return self.next();
                        continue;
                    }
                    let start = cmp::max(cursor, max_segment);

                    let mapping = Mapping {
                        hpa: start,
                        gpa: start,
                        size: region.end - start,
                        repeat: 1,
                        ops: region.ops,
                        resource_kind: region.resource_kind,
                    };
                    return Some(mapping);
                }
                (Some(next_segment), Some(next_region)) => {
                    assert!(
                        self.cursor <= next_region,
                        "self.cursor 0x{:013x}, next_region 0x{:013x}",
                        self.cursor,
                        next_region
                    );
                    assert!(
                        self.cursor <= next_segment,
                        "self.cursor 0x{:013x}, next_segment 0x{:013x}",
                        self.cursor,
                        next_segment
                    );

                    if next_segment <= next_region {
                        // If a segment comes first, build a segment remapper and retry
                        self.cursor = next_segment;
                        let segment = self.remap_commands_iter.next().unwrap();
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
                        //return self.next();
                        continue;
                    } else {
                        // A region comes first, we emit a mapping if no segment covered it
                        let region = self.regions.peek().copied().unwrap();
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
                                resource_kind: region.resource_kind,
                            };

                            return Some(mapping);
                        } else {
                            // Otherwise move on to next iteration
                            //return self.next();
                            continue;
                        }
                    }
                }
            }
        }
    }
}

/// Creates all mapping objects for the given Segment by matching
/// the segment to the given regions
#[derive(Clone)]
struct SingleSegmentIterator<'a, T: MemoryColoring + Clone + Default> {
    regions: Peekable<PermissionIterator<'a, T>>,
    next_region: Option<MemoryPermission>,
    cursor: usize,
    segment: Segment,
}

impl<'a, T: MemoryColoring + Clone + Default> SingleSegmentIterator<'a, T> {
    fn next(&mut self) -> Option<Mapping> {
        // Retrieve the current region and segment
        let segment = &self.segment;
        let mut next_region: Option<MemoryPermission> = self.next_region;
        if next_region.is_none() {
            // Move to the next region
            next_region = self.regions.next();
        }
        //luca: seek past regions that come "before" our segment in HPA space
        loop {
            match next_region {
                Some(region) if region.end <= segment.hpa => {
                    // Move to next region
                    next_region = self.regions.next();
                }
                _ => break,
            }
        }
        //luca: no regions overlap our segment => done
        let Some(region) = next_region else {
            if self.cursor <= segment.hpa + segment.size {
                self.cursor = segment.hpa + segment.size;
            }
            return None;
        };

        /*luca: if we are here, we have a region for our segment.
         * Our segment might spand multiple regions. Thus, we next update
         * the cursor, to keep track where exactly in memory we are
         * The purpose of the region, is to give us the ptracker.permissions for the mapping
         * that we are about to create.
         * The logic checks are mostly based on the logic for the mapping creation at the end
         * of this function
         */

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
            resource_kind: region.resource_kind,
        };
        self.cursor = next_cusor;
        Some(mapping)
    }
}

/// A simple iterator over the remapper segments without any hidden logic
#[derive(Clone)]
pub struct RemapperSegmentIterator<'a, const SIMPLE: usize, const COMPACT: usize> {
    remapper: &'a Remapper<SIMPLE, COMPACT>,
    next_segment: Option<Handle<Segment>>,
}

impl<'a, const SIMPLE: usize, const COMPACT: usize> Iterator
    for RemapperSegmentIterator<'a, SIMPLE, COMPACT>
{
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
    use mmu::memory_coloring::color_to_phys::PhysRange;
    use mmu::memory_coloring::{self, ActiveMemoryColoring, DummyMemoryColoring, MyBitmap};
    use utils::HostPhysAddr;

    use super::*;
    use crate::config::NB_TRACKER;
    use crate::debug::snap;
    use crate::region::{TrackerPool, EMPTY_REGION};
    use crate::{RegionTracker, ResourceKind, MEMOPS_ALL};

    #[derive(Clone, Default)]
    struct RangeBasedTestColoring {
        //tuples of phys range with the corresponding color
        ranges: Vec<(PhysRange, u64)>,
    }

    impl RangeBasedTestColoring {
        pub fn new(ranges: Vec<(PhysRange, u64)>) -> Self {
            Self { ranges }
        }
    }

    impl MemoryColoring for RangeBasedTestColoring {
        const COLOR_COUNT: usize = memory_coloring::MAX_COLOR_COUNT;

        const BYTES_FOR_COLOR_BITMAP: usize = memory_coloring::MAX_COLOR_BITMAP_BYTES;

        type Bitmap = MyBitmap<{ Self::BYTES_FOR_COLOR_BITMAP }, { Self::COLOR_COUNT }>;

        fn compute_color(&self, frame: HostPhysAddr) -> u64 {
            for (range, color) in &self.ranges {
                if range.start <= frame.as_usize() && frame.as_usize() < range.end {
                    return *color;
                }
            }
            panic!("invalid test valid coloring config")
        }

        fn new() -> Self {
            Self {
                ranges: todo!("not sure how to impelement for this test coloring"),
            }
        }
    }

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
    fn performance_debugging() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<4, 4> = Remapper::new();
        let coloring = DummyMemoryColoring {};

        let allowed_colors = (0, DummyMemoryColoring::COLOR_COUNT - 8);

        //copy of the regions for actual memory config where performance is slow
        let regions: Vec<(usize, usize, bool)> = vec![
            (0x0000000000000, 0x0000000001000, false),
            (0x0000000001000, 0x00000001c6000, true),
            (0x00000001c6000, 0x0000000800000, false),
            (0x0000000800000, 0x0000000808000, true),
            (0x0000000808000, 0x000000080b000, false),
            (0x000000080b000, 0x000000080c000, true),
            (0x000000080c000, 0x0000000810000, false),
            (0x0000000810000, 0x0000000900000, true),
            (0x0000000900000, 0x000007faef000, false),
            (0x000007faef000, 0x000007fbff000, true),
            (0x000007fbff000, 0x000007ff78000, false),
            (0x000007ff78000, 0x00000fed90000, true),
            (0x00000fed90000, 0x00000fed91000, true),
            (0x00000fed91000, 0x0000100000000, true),
            (0x0000100000000, 0x000023b600000, false),
            (0x000023b600000, 0x0000240000000, true),
        ];
        let start_hpa = regions[0].0;
        let end_hpa = regions.last().unwrap().1;
        //add regions to tracker
        for (start, end, is_device) in regions {
            let rk = if is_device {
                ResourceKind::Device
            } else {
                ResourceKind::ram_with_all_partitions()
            };
            tracker
                .add_region(start, end, MEMOPS_ALL, rk, &mut pool)
                .unwrap();
        }
        //create compact remapping
        remapper
            .map_compactified_range(allowed_colors, true, 0, tracker.iter(&pool))
            .unwrap();

        //fast until here

        let remap_iter = remapper.new_remap_iter(
            coloring.clone(),
            tracker.permissions(&pool, coloring.clone(), None, true),
        );
        let remap_count = remap_iter.count();
        println!("Have {} remaps", remap_count);
    }

    #[test]
    fn simple_compactify() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let coloring = RangeBasedTestColoring::new(vec![
            (
                PhysRange {
                    start: 0x0_000,
                    end: 0x1_000,
                },
                0,
            ),
            (
                PhysRange {
                    start: 0x1_000,
                    end: 0x5_000,
                },
                1,
            ),
            (
                PhysRange {
                    //5 to 10
                    start: 0x5_000,
                    end: 0xa_000,
                },
                0,
            ),
            (
                //We give the device a special color to ensure that its color is actually ignored
                PhysRange {
                    //10 to 11
                    start: 0xa_000,
                    end: 0xb_000,
                },
                2,
            ),
            (
                PhysRange {
                    //11 to 15
                    start: 0xb_000,
                    end: 0xf_000,
                },
                1,
            ),
            (
                PhysRange {
                    //15 to 20
                    start: 0xf_000,
                    end: 0x14_000,
                },
                0,
            ),
        ]);
        // Mem Layout: [RAM A | Device B | RAM C ]
        //Using our coloring
        //- RAM A: 6 pages with color 0, 4 pages with color 1
        //- RAM B: 5 pages with color 0, 5 pages with color 1

        //11 ram pages + 1 device page
        const WANT_END_RAM_GPA: GuestPhysAddr = GuestPhysAddr::new(0xc_000);
        const WANT_END_DEVICE_GPA: GuestPhysAddr = GuestPhysAddr::new(0xb_000);

        //RAM A
        tracker
            .add_region(
                0x0_000,
                0xa_000,
                MEMOPS_ALL,
                ResourceKind::ram_with_partitions(&[0]),
                &mut pool,
            )
            .unwrap();
        // Device B
        tracker
            .add_region(
                0xa_000,
                0xb_000,
                MEMOPS_ALL,
                ResourceKind::Device,
                &mut pool,
            )
            .unwrap();
        //RAM C
        tracker
            .add_region(
                0xb_000,
                0x14_000,
                MEMOPS_ALL,
                ResourceKind::ram_with_partitions(&[0]),
                &mut pool,
            )
            .unwrap();

        //program remapper to compactify
        /*let (end_ram_gpa, end_device_gpa) = compactify_colors_in_gpa_space(
            &mut remapper,
            tracker.permissions(&pool, coloring.clone(), None, true),
            GuestPhysAddr::new(0),
        )
        .expect("compactify failed");*/
        remapper
            .map_compactified_range((0, 1), true, 0, tracker.iter(&pool))
            .unwrap();

        /*HPA_{start}, HPA_{end}, GPA_{start}, results are entered into the rempapper
         * ordered by their HPA_{start} not by their GPA_{start}
         */
        snap(
            concat!(
                "{",
                "[0x0, 0x1000 at 0x0, rep 1 | RWXS] -> ", //Part 1 of RAM A
                "[0x5000, 0xa000 at 0x1000, rep 1 | RWXS] -> ", //Part 2 of RAM A
                "[0xa000, 0xb000 at 0xa000, rep 1 | RWXS] -> ", //Device B,
                "[0xf000, 0x13000 at 0x6000, rep 1 | RWXS] -> ", // RAM C : stuff that fits before hitting device
                "[0x13000, 0x14000 at 0xb000, rep 1 | RWXS]", // RAM C: stuff that did not fit before hitting device
                "}"
            ),
            &remapper.new_remap_iter(
                coloring.clone(),
                tracker.permissions(&pool, coloring.clone(), None, true),
            ),
        );
    }

    #[test]
    fn compactify_with_gap_to_last_device() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let coloring = RangeBasedTestColoring::new(vec![
            (
                PhysRange {
                    start: 0x0_000,
                    end: 0x1_000,
                },
                0,
            ),
            (
                PhysRange {
                    start: 0x1_000,
                    end: 0x5_000,
                },
                1,
            ),
            (
                PhysRange {
                    start: 0x5_000,
                    end: 0xa_000,
                },
                0,
            ),
            (
                PhysRange {
                    //catch all
                    start: 0xa_000,
                    end: 0x10_000,
                },
                1,
            ),
        ]);
        // Mem Layout: [RAM A | Device B]

        const WANT_END_RAM_GPA: GuestPhysAddr = GuestPhysAddr::new(0x6_000);
        const WANT_END_DEVICE_GPA: GuestPhysAddr = GuestPhysAddr::new(0xf_000);

        //RAM A
        tracker
            .add_region(
                0x0_000,
                0xa_000,
                MEMOPS_ALL,
                ResourceKind::ram_with_partitions(&[0]),
                &mut pool,
            )
            .unwrap();
        // Device B
        tracker
            .add_region(
                0xe_000,
                0xf_000,
                MEMOPS_ALL,
                ResourceKind::Device,
                &mut pool,
            )
            .unwrap();

        //program remapper to compactify
        remapper
            .map_compactified_range((0, 1), true, 0, tracker.iter(&pool))
            .unwrap();

        /*HPA_{start}, HPA_{end}, GPA_{start}, results are entered into the rempapper
         * ordered by their HPA_{start} not by their GPA_{start}
         */
        snap(
            concat!(
                "{",
                "[0x0, 0x1000 at 0x0, rep 1 | RWXS] -> ", //Part 1 of RAM A
                "[0x5000, 0xa000 at 0x1000, rep 1 | RWXS] -> ", //Part 2 of RAM A
                "[0xe000, 0xf000 at 0xe000, rep 1 | RWXS]", //Device B,
                "}"
            ),
            &remapper.new_remap_iter(
                coloring.clone(),
                tracker.permissions(&pool, coloring.clone(), None, true),
            ),
        );
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
    fn compactified_remap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let coloring = RangeBasedTestColoring::new(vec![
            (
                PhysRange {
                    start: 0x0_000,
                    end: 0x1_000,
                },
                0,
            ),
            (
                PhysRange {
                    start: 0x0_000,
                    end: 0x2_000,
                },
                1,
            ),
            (
                PhysRange {
                    start: 0x2_000,
                    end: 0x3_000,
                },
                0,
            ),
            (
                PhysRange {
                    start: 0x3_000,
                    end: 0x4_000,
                },
                1,
            ),
            (
                PhysRange {
                    start: 0x4_000,
                    end: 0x1000_000,
                },
                1,
            ),
        ]);
        tracker
            .add_region(
                0x0_000,
                0x8_000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        /*for x in 1..120 {
            tracker
                .add_region(
                    0x8_000 + (x * 0x1_000),
                    0x8_000 + (x * 0x1_000) + 0x1_000,
                    MEMOPS_ALL,
                    ResourceKind::ram_with_all_partitions(),
                    &mut pool,
                )
                .unwrap();
        }*/

        remapper
            .map_compactified_range((0, 1), true, 0x10_000, tracker.iter(&pool))
            .expect("failed to add compactified mapping");
        remapper
            .map_compactified_range((1, 2), true, 0x20_000, tracker.iter(&pool))
            .expect("failed to add compactified mapping");

        println!("merged remap iter");
        let merged_remap_iter =
            remapper.new_merged_remap_iter::<RangeBasedTestColoring>(coloring.clone());
        for x in merged_remap_iter {
            println!("{:x?}", x);
        }
        println!("remappings");
        for x in remapper.new_remap_iter(
            coloring.clone(),
            tracker.permissions(&pool, coloring.clone(), None, true),
        ) {
            println!("\n{:x?}\n", x);
        }
    }

    #[test]
    fn remap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let all_same_color = RangeBasedTestColoring::new(vec![(
            PhysRange {
                start: 0x0,
                end: 0x10000,
            },
            0,
        )]);

        // Add a first region
        tracker
            .add_region(
                0x1000,
                0x2000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x1000, 0x2000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        snap(
            "{[0x1000, 0x2000 at 0x1000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(
                all_same_color.clone(),
                tracker.permissions(&pool, all_same_color.clone(), None, true),
            ),
        );

        // Remap that region
        remapper.map_range(0x1_000, 0x10_010, 0x1000, 1).unwrap();
        snap(
            "{[0x1000, 0x2000 at 0x10010, rep 1 | RWXS]}",
            &remapper.new_remap_iter(
                all_same_color.clone(),
                tracker.permissions(&pool, all_same_color.clone(), None, true),
            ),
        );

        // Let's add a few more!
        tracker
            .add_region(
                0x3000,
                0x4000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        tracker
            .add_region(
                0x4000,
                0x5000,
                MemOps::READ,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x1000, 0x2000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))] -> [0x3000, 0x4000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))] -> [0x4000, 0x5000 | 1 (1 - 0 - 0 - 0 - RAM.(ALL 1))]}", &tracker.iter(&pool));
        snap(
            "{[0x1000, 0x2000 at 0x10010, rep 1 | RWXS] -> [0x3000, 0x4000 at 0x3000, rep 1 | RWXS] -> [0x4000, 0x5000 at 0x4000, rep 1 | R___]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );

        // And (partially) remap those
        remapper.map_range(0x3000, 0x13000, 0x800, 1).unwrap();
        snap(
            "{[0x1000, 0x2000 at 0x10010, rep 1 | RWXS] -> [0x3000, 0x3800 at 0x13000, rep 1 | RWXS] -> [0x3800, 0x4000 at 0x3800, rep 1 | RWXS] -> [0x4000, 0x5000 at 0x4000, rep 1 | R___]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool,all_same_color.clone(),None,true)),
        );
        remapper.map_range(0x3800, 0x23800, 0x800, 1).unwrap();
        snap(
            "{[0x1000, 0x2000 at 0x10010, rep 1 | RWXS] -> [0x3000, 0x3800 at 0x13000, rep 1 | RWXS] -> [0x3800, 0x4000 at 0x23800, rep 1 | RWXS] -> [0x4000, 0x5000 at 0x4000, rep 1 | R___]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );
        remapper.map_range(0x4000, 0x14000, 0x1000, 3).unwrap();
        snap(
            "{[0x1000, 0x2000 at 0x10010, rep 1 | RWXS] -> [0x3000, 0x3800 at 0x13000, rep 1 | RWXS] -> [0x3800, 0x4000 at 0x23800, rep 1 | RWXS] -> [0x4000, 0x5000 at 0x14000, rep 3 | R___]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );

        // Unmap some segments
        remapper.unmap_range(0x3800, 0x800).unwrap();
        snap(
            "{[0x1000, 0x2000 at 0x10010, rep 1 | RWXS] -> [0x3000, 0x3800 at 0x13000, rep 1 | RWXS] -> [0x3800, 0x4000 at 0x3800, rep 1 | RWXS] -> [0x4000, 0x5000 at 0x14000, rep 3 | R___]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );
        remapper.unmap_range(0x3000, 0x800).unwrap();
        snap(
            "{[0x1000, 0x2000 at 0x10010, rep 1 | RWXS] -> [0x3000, 0x4000 at 0x3000, rep 1 | RWXS] -> [0x4000, 0x5000 at 0x14000, rep 3 | R___]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );

        // Delete regions but not the segments yet
        tracker
            .remove_region(
                0x4000,
                0x5000,
                MemOps::READ,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x1000, 0x2000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))] -> [0x3000, 0x4000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        snap(
            "{[0x1000, 0x2000 at 0x10010, rep 1 | RWXS] -> [0x3000, 0x4000 at 0x3000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );

        // Unmap more segments
        remapper.unmap_range(0x4000, 0x1000).unwrap();
        snap(
            "{[0x1000, 0x2000 at 0x10010, rep 1 | RWXS] -> [0x3000, 0x4000 at 0x3000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );
        remapper.unmap_range(0x1000, 0x1000).unwrap();
        snap(
            "{[0x1000, 0x2000 at 0x1000, rep 1 | RWXS] -> [0x3000, 0x4000 at 0x3000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );
    }

    #[test]
    fn cross_regions() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let all_same_color = RangeBasedTestColoring::new(vec![(
            PhysRange {
                start: 0x0,
                end: 0x10000,
            },
            0,
        )]);

        // Add two regions with hole
        tracker
            .add_region(
                0x1000,
                0x3000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        tracker
            .add_region(
                0x4000,
                0x6000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x1000, 0x3000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))] -> [0x4000, 0x6000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        snap(
            "{[0x1000, 0x3000 at 0x1000, rep 1 | RWXS] -> [0x4000, 0x6000 at 0x4000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );

        // Create a mapping that cross the region boundary
        remapper.map_range(0x2000, 0x10000, 0x10000, 1).unwrap();
        snap(
            "{[0x1000, 0x2000 at 0x1000, rep 1 | RWXS] -> [0x2000, 0x3000 at 0x10000, rep 1 | RWXS] -> [0x4000, 0x6000 at 0x12000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );
    }

    #[test]
    fn backward_overlap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let all_same_color = RangeBasedTestColoring::new(vec![(
            PhysRange {
                start: 0x0,
                end: 0x10000,
            },
            0,
        )]);

        tracker
            .add_region(
                0x1000,
                0x4000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        tracker
            .add_region(
                0x3000,
                0x4000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x1000, 0x3000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))] -> [0x3000, 0x4000 | 2 (2 - 2 - 2 - 2 - RAM.(ALL 2))]}",
            &tracker.iter(&pool),
        );

        remapper.map_range(0x1000, 0x10000, 0x3000, 1).unwrap();
        remapper.map_range(0x3000, 0x5000, 0x1000, 1).unwrap();
        snap(
            "{[0x1000, 0x4000 at 0x10000, rep 1] -> [0x3000, 0x4000 at 0x5000, rep 1]}",
            remapper.iter_segments(),
        );
        snap(
            // Note: here for some reason the tracker do not properly merge the two contiguous
            // regions. We should figure that out at some point and optimize the tracker.
            "{[0x1000, 0x3000 at 0x10000, rep 1 | RWXS] -> [0x3000, 0x4000 at 0x12000, rep 1 | RWXS] -> [0x3000, 0x4000 at 0x5000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color,None,true)),
        );
    }

    #[test]
    fn remapper_wip_coloring_test_simple() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let all_same_color = RangeBasedTestColoring::new(vec![(
            PhysRange {
                start: 0x0,
                end: 0x1_000_000,
            },
            0,
        )]);

        tracker
            .add_region(
                0x1000,
                0x4000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x1000, 0x4000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        remapper.map_range(0x1_000, 0x10_000, 0x10, 1).unwrap();
        //format: map [HPA_s, HPA_e contig at GPA_s]
        //strategy: everything that is not explicity remapped will be identity mapped
        snap(
            "{[0x1000, 0x1010 at 0x10000, rep 1 | RWXS] -> [0x1010, 0x4000 at 0x1010, rep 1 | RWXS]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );
    }

    #[test]
    fn forward_overlap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let all_same_color = RangeBasedTestColoring::new(vec![(
            PhysRange {
                start: 0x0,
                end: 0x1_000_000,
            },
            0,
        )]);

        tracker
            .add_region(
                0x1_000,
                0x4_000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x1000, 0x4000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        snap(
            "{[0x1000, 0x4000 | RWXS]}",
            tracker.permissions(&pool, all_same_color.clone(), None, true),
        );

        remapper.map_range(0x2_000, 0x10_000, 0x1000, 1).unwrap();
        remapper.map_range(0x3_000, 0x20_000, 0x1000, 1).unwrap();

        println!(
            "Ptracker.permissions Iterator: {}",
            tracker.permissions(&pool, all_same_color.clone(), None, true)
        );
        snap(
            "{[0x1000, 0x2000 at 0x1000, rep 1 | RWXS] -> [0x2000, 0x3000 at 0x10000, rep 1 | RWXS] -> [0x3000, 0x4000 at 0x20000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool, all_same_color.clone(),None,true)),
        );

        remapper.map_range(0x1_000, 0x30_000, 0x3_000, 1).unwrap();
        snap(
            "{[0x1000, 0x4000 at 0x30000, rep 1 | RWXS] -> [0x2000, 0x3000 at 0x10000, rep 1 | RWXS] -> [0x3000, 0x4000 at 0x20000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(all_same_color.clone(),tracker.permissions(&pool,all_same_color.clone(),None,true)),
        );
    }

    #[test]
    fn update_region() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let all_same_color = RangeBasedTestColoring::new(vec![(
            PhysRange {
                start: 0x0,
                end: 0x1_000_000,
            },
            0,
        )]);

        // Add one region
        tracker
            .add_region(
                0x1000,
                0x6000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x1000, 0x6000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        snap(
            "{[0x1000, 0x6000 at 0x1000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(
                all_same_color.clone(),
                tracker.permissions(&pool, all_same_color.clone(), None, true),
            ),
        );

        // Remap the whole region
        remapper.map_range(0x1000, 0x10000, 0x5000, 1).unwrap();
        snap(
            "{[0x1000, 0x6000 at 0x10000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(
                all_same_color.clone(),
                tracker.permissions(&pool, all_same_color.clone(), None, true),
            ),
        );

        // Split the region in two
        tracker
            .remove_region(
                0x1000,
                0x6000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        tracker
            .add_region(
                0x1000,
                0x2000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        tracker
            .add_region(
                0x2000,
                0x4000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        tracker
            .add_region(
                0x4000,
                0x6000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x1000, 0x6000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        snap(
            "{[0x1000, 0x6000 at 0x10000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(
                all_same_color.clone(),
                tracker.permissions(&pool, all_same_color.clone(), None, true),
            ),
        );
    }

    #[test]
    fn split_region() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();

        tracker
            .add_region(
                0x12fcb6000,
                0x12fcf6000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        remapper
            .map_range(0x12fcb6000, 0xfffc0000, 0x40000, 1)
            .unwrap();
        tracker
            .add_region(
                0x12fcd6000,
                0x12fcf6000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        remapper
            .map_range(0x12fcd6000, 0xe0000, 0x20000, 1)
            .unwrap();
        snap("{[0x12fcb6000, 0x12fcd6000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))] -> [0x12fcd6000, 0x12fcf6000 | 2 (2 - 2 - 2 - 2 - RAM.(ALL 2))]}", &tracker.iter(&pool));
        snap("{[0x12fcb6000, 0x12fcf6000 at 0xfffc0000, rep 1] -> [0x12fcd6000, 0x12fcf6000 at 0xe0000, rep 1]}", remapper.iter_segments());
    }

    #[test]
    fn gpa_overlap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32, 8> = Remapper::new();
        let all_same_color = RangeBasedTestColoring::new(vec![(
            PhysRange {
                start: 0x0,
                end: 0x1_000_000,
            },
            0,
        )]);

        tracker
            .add_region(
                0x2000,
                0x8000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x2000, 0x8000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        remapper.map_range(0x2000, 0x20000, 0x6000, 1).unwrap();
        snap(
            "{[0x2000, 0x8000 at 0x20000, rep 1]}",
            remapper.iter_segments(),
        );
        snap(
            "{[0x2000, 0x8000 at 0x20000, rep 1 | RWXS]}",
            &remapper.new_remap_iter(
                all_same_color.clone(),
                tracker.permissions(&pool, all_same_color.clone(), None, true),
            ),
        );

        tracker
            .add_region(
                0x8000,
                0xa000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x2000, 0xa000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        let err = remapper.map_range(0x8000, 0x22000, 0x2000, 1);
        assert!(err.is_err());
        assert_eq!(err.err().unwrap(), CapaError::AlreadyAliased);
    }

    #[test]
    fn debug_iterator() {
        let mut remapper: Remapper<32, 8> = Remapper::new();

        remapper.map_range(0x10, 0x100, 0x20, 2).unwrap();
        snap("{[0x10, 0x30 at 0x100, rep 2]}", &remapper.iter_segments());
        remapper.map_range(0x30, 0x200, 0x20, 1).unwrap();
        snap(
            "{[0x10, 0x30 at 0x100, rep 2] -> [0x30, 0x50 at 0x200, rep 1]}",
            &remapper.iter_segments(),
        );
        remapper.map_range(0x80, 0x300, 0x20, 1).unwrap();
        snap("{[0x10, 0x30 at 0x100, rep 2] -> [0x30, 0x50 at 0x200, rep 1] -> [0x80, 0xa0 at 0x300, rep 1]}", &remapper.iter_segments());
    }

    #[test]
    fn single_segment_iterator() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let all_same_color = RangeBasedTestColoring::new(vec![(
            PhysRange {
                start: 0x0,
                end: 0x1_000_000,
            },
            0,
        )]);

        // Create a single region
        tracker
            .add_region(
                0x3000,
                0x6000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x3000, 0x6000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );
        let iterator = SingleSegmentIterator {
            regions: tracker
                .permissions(&pool, all_same_color.clone(), None, true)
                .peekable(),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x1000, 0x10000, 0x1000, 1),
        };
        snap("", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker
                .permissions(&pool, all_same_color.clone(), None, true)
                .peekable(),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x7000, 0x10000, 0x1000, 1),
        };
        snap("", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker
                .permissions(&pool, all_same_color.clone(), None, true)
                .peekable(),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x2000, 0x10000, 0x2000, 1),
        };
        snap("[0x3000, 0x4000 at 0x11000, rep 1 | RWXS]", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker
                .permissions(&pool, all_same_color.clone(), None, true)
                .peekable(),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x5000, 0x10000, 0x2000, 1),
        };
        snap("[0x5000, 0x6000 at 0x10000, rep 1 | RWXS]", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker
                .permissions(&pool, all_same_color.clone(), None, true)
                .peekable(),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x4000, 0x10000, 0x1000, 1),
        };
        snap("[0x4000, 0x5000 at 0x10000, rep 1 | RWXS]", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker
                .permissions(&pool, all_same_color.clone(), None, true)
                .peekable(),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x2000, 0x10000, 0x5000, 1),
        };
        snap("[0x3000, 0x6000 at 0x11000, rep 1 | RWXS]", iterator);

        // Let's experiment with multiple regions now
        tracker
            .add_region(
                0x7000,
                0x8000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x3000, 0x6000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))] -> [0x7000, 0x8000 | 1 (1 - 1 - 1 - 1 - RAM.(ALL 1))]}",
            &tracker.iter(&pool),
        );

        let iterator = SingleSegmentIterator {
            regions: tracker
                .permissions(&pool, all_same_color.clone(), None, true)
                .peekable(),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x2000, 0x10000, 0x8000, 1),
        };
        snap(
            "[0x3000, 0x6000 at 0x11000, rep 1 | RWXS] -> [0x7000, 0x8000 at 0x15000, rep 1 | RWXS]",
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

impl<'a, const SIMPLE: usize, const COMPACT: usize, T: MemoryColoring + Clone + Default>
    fmt::Display for RemapIterator<'a, SIMPLE, COMPACT, T>
{
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

impl<'a, const SIMPLE: usize, const COMPACT: usize> fmt::Display
    for RemapperSegmentIterator<'a, SIMPLE, COMPACT>
{
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

impl<'a, T: MemoryColoring + Clone + Default> fmt::Display for SingleSegmentIterator<'a, T> {
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
