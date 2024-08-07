//! Remapper
//!
//! The remapper is not part of the capa-engine, but a wrapper that can be used to keep trap of
//! virtual addresses for platform such as x86 that needs to emulate second-level page tables.

use core::{array, cmp, fmt};

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

pub struct Remapper<const N: usize> {
    //simple remappings
    segments: GenArena<Segment, N>,
    //complex, compactifier remappings
    compact_remaps: GenArena<CompactRemap, N>,
    //TODO: store memory coloring
    head: Option<Handle<Segment>>,
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
impl<const N: usize> Remapper<N> {
    pub const fn new() -> Self {
        let v = Remapper {
            segments: GenArena::new([EMPTY_SEGMENT; N]),
            head: None,
            compact_remaps: GenArena::new([CompactRemap::empty(); N]),
            remapper_region_pool: TrackerPool::new([EMPTY_REGION; NB_TRACKER]),
        };
        let a = 10;
        v
    }

    pub fn new_merged_remap_iter<'a, T>(&'a self, coloring: T) -> MergedRemapIter<'a, N, T>
    where
        T: MemoryColoring + Clone + Default,
    {
        //panic!("entering new merged remap iter");
        log::info!("creating new_merged_remap_iter");
        let simple = &self.segments;
        let mut compactified_iters: [CompatifiedMappingIter<'a, T>; N] =
            array::from_fn(|_| CompatifiedMappingIter::default());
        let mut compactified_len = 0;
        //panic!("before loop");
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
        //panic!("before new call");
        MergedRemapIter::new(simple, compactified_iters, compactified_len)
    }

    pub fn new_remap_iter<'a, T: MemoryColoring + Clone + Default>(
        &'a self,
        coloring: T,
        regions: PermissionIterator<'a, T>,
    ) -> RemapIterator<'a, N, T> {
        log::info!("remapper:new_remap_iter");
        RemapIterator {
            regions,
            next_region_start: None,
            remap_commands_iter: self.new_merged_remap_iter(coloring),
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

    pub fn map_compactified_range(
        &mut self,
        color_range: (usize, usize),
        include_devices: bool,
        start_gpa: usize,
        regions_iter: RegionIterator,
    ) -> Result<(), CapaError> {
        log::info!("remapper::map_compactified_range");
        //panic!("start of map_compactified in remapper"); // get here
        let mut remap_region_snapshot = RegionTracker::new();
        //panic!("allocated region tracker"); //get here
        for (a, x) in regions_iter {
            panic!("start of first iteration"); //if remap_region_snapshot is commented in, we don't reach this location. If we remove it, we get here
            let is_device = match x.get_resource_kind() {
                RegionResourceKind::Device => true,
                _ => false,
            };
            if is_device && !include_devices {
                continue;
            }
            log::info!(
                "remapper::map_compactified_range : adding region start 0x{:013x}, end 0x{:013x}",
                x.get_start(),
                x.get_end()
            );
            remap_region_snapshot
                .add_region(
                    x.get_start(),
                    x.get_end(),
                    x.get_ops(),
                    ResourceKind::from(&x.get_resource_kind()),
                    &mut self.remapper_region_pool,
                )
                .expect("remapper::map_compactified_range failed to add region");
            //panic!("end of first iteration");
        }
        panic!("after regions_iter loop");
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

        //panic!("end of compactified mapping");
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

    pub fn unmap_gpa_range(&mut self, gpa: usize, size: usize) -> Result<(), ()> {
        let Some(head) = self.head else {
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
                        self.head = next;
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
}

// ——————————————————————————————— Iterators ———————————————————————————————— //

#[derive(Clone)]
pub struct RemapIterator<'a, const N: usize, T: MemoryColoring + Clone + Default> {
    //luca: deduplicated view of the memory ptracker.permissions for our domain
    regions: PermissionIterator<'a, T>,
    //luca: just simple iterator over existing segments
    remap_commands_iter: MergedRemapIter<'a, N, T>,
    cursor: usize,
    next_region_start: Option<usize>,
    next_segment_start: Option<usize>,
    max_segment: Option<usize>,
    ongoing_segment: Option<SingleSegmentIterator<'a, T>>,
}

impl<'a, const N: usize, T: MemoryColoring + Clone + Default> Iterator for RemapIterator<'a, N, T> {
    type Item = Mapping;

    /*luca: initial state
    RemapIterator {
           regions,
           next_region_start: None,
           //luca: from prior runs
           segments: self.iter_segments(),
           next_segment_start: None,
           cursor: 0,
           ongoing_segment: None,
           max_segment: None,
       }
    */
    fn next(&mut self) -> Option<Self::Item> {
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
            self.next_region_start = self.regions.clone().next().map(|region| region.start);
        }
        if self.next_segment_start.is_none() {
            self.next_segment_start = self
                .remap_commands_iter
                .clone()
                .next()
                .map(|segment| segment.hpa);
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
                //luca: largest start addr of a segment?
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
                    resource_kind: region.resource_kind,
                };
                return Some(mapping);
            }
            (Some(next_segment), Some(next_region)) => {
                assert!(self.cursor <= next_region);
                assert!(self.cursor <= next_segment);

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
                            resource_kind: region.resource_kind,
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

/// Creates all mapping objects for the given Segment by matching
/// the segment to the given regions
#[derive(Clone)]
struct SingleSegmentIterator<'a, T: MemoryColoring + Clone + Default> {
    regions: PermissionIterator<'a, T>,
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

/// This will create create a contiguous GPA space mappings for the possibly scattered
/// HPA memory range produced by the PermissionIterator (due to coloring).
/// The strategy is to keep device memory identity. The RAM memory is remapped contiguously starting at
/// `start_gpa`, with the expection of skipping over device memory.
/// # Arguments
/// - `map_cb` : Called for each (HPA,GPA,size) remapping that we generated. Store this e.g. in the domain's remapper
/// - `permission_iter` : generates the HPA memory ranges that we want to remap
/// - `start_gpa` first GPA of the contiguous mapping
pub fn compactify_colors_in_gpa_space_cb_mapper<
    T: MemoryColoring + Clone + Default,
    F: FnMut(HostPhysAddr, GuestPhysAddr, usize, usize) -> Result<(), CapaError>,
>(
    map_cb: &mut F,
    permission_iter: PermissionIterator<T>,
    start_gpa: GuestPhysAddr,
) -> Result<(GuestPhysAddr, Option<GuestPhysAddr>), CapaError> {
    let mut next_blocked_iter = permission_iter.clone().filter(|v| match v.resource_kind {
        ResourceKind::RAM(_) => false,
        ResourceKind::Device => true,
    });
    let mut next_blocked = next_blocked_iter.next();

    let mut next_ram_gpa = start_gpa.as_usize();
    let mut highest_device_gpa: Option<GuestPhysAddr> = None;
    //skip over device regions that have smaller addr than first ram region
    let first_ram_region = permission_iter
        .clone()
        .filter(|v| {
            ResourceKind::same_kind(&v.resource_kind, &ResourceKind::ram_with_all_partitions())
        })
        .next()
        .ok_or(CapaError::InternalRegionError)?;

    while let Some(nb) = next_blocked.as_ref() {
        if nb.start > first_ram_region.start {
            break;
        }
        next_ram_gpa += nb.end - nb.start;
        next_blocked = next_blocked_iter.next();
    }

    let mut _mapped_ram_bytes = 0;
    let mut _mapped_device_bytes = 0;
    //total number of contig phys ranges that we used to back the GPA RAM space
    let mut _total_ram_range_count = 0;
    //counts the number of created mappings
    let mut mapping_count = 0;
    for (_, range) in permission_iter.enumerate() {
        if mapping_count > 0 && mapping_count % 10000 == 0 {
            log::info!("Used {:08} remappings so far", mapping_count);
        }
        /* Observations/Assumptions:
         * The results of the iterator are sorted, i.e. we go through the address space "left to right".
         * With partititions, a memory range might be smaller that its actually physical bounds, however
         * it cannot be larger. Thus, we cannot end up in the situation where we want to map an identity
         * mapped device but have already used that part of the address space for one of the preceedign
         * mappings
         *
         * TODO: preserve order when adding new colors later on
         */
        let resource_kind = range.resource_kind;
        match resource_kind {
            ResourceKind::RAM(_) => {
                //figure out amout of bytes we can map before hitting the next range blocked for a device
                let mut remaining_chunk_bytes = range.size();
                while remaining_chunk_bytes > 0 {
                    let map_size;
                    let mut advance_next_blocked = false;
                    match &next_blocked {
                        Some(next_blocked) => {
                            //for device mem we need to compare gour gpa with hpa, because we will passtrhough/identity map them
                            assert!(next_ram_gpa <= next_blocked.start);
                            let bytes_until_blocked = next_blocked.start - next_ram_gpa;
                            assert!(bytes_until_blocked > 0, "bytes untill blocked was 0. next_blocked.hpa = 0x{:x}, next_ram_gpa 0x{:x}", next_blocked.start, next_ram_gpa);
                            if remaining_chunk_bytes < bytes_until_blocked {
                                map_size = remaining_chunk_bytes;
                            } else {
                                advance_next_blocked = true;
                                map_size = bytes_until_blocked;
                            }
                        }
                        None => {
                            //No more blocked ranges -> can map everything
                            map_size = remaining_chunk_bytes;
                        }
                    }

                    assert_eq!(next_ram_gpa % PAGE_SIZE, 0, "next_ram_gpa is not aligned");
                    assert_eq!(map_size % PAGE_SIZE, 0, "map_size ist not aligned");
                    assert!(map_size > 0);

                    map_cb(HostPhysAddr::new(range.end - remaining_chunk_bytes), GuestPhysAddr::new(next_ram_gpa), map_size,1).map_err(|e| {
                            log::error!("failed to map HPA 0x{:013x} at GPA 0x{:013x} for 0x{:x} bytes in remappar",range.end - remaining_chunk_bytes, next_ram_gpa, map_size
                        );
                            e
                        })?;
                    _mapped_ram_bytes += map_size;
                    remaining_chunk_bytes -= map_size;
                    mapping_count += 1;
                    next_ram_gpa += map_size;
                    if advance_next_blocked {
                        let mut cur_blocked = next_blocked.ok_or_else(|| {
                            log::error!("advance_next_blocked true but next block was None");
                            CapaError::InternalRegionError
                        })?;

                        assert_eq!(next_ram_gpa, cur_blocked.start,"Requested to advance next blocked, but have not hit it yet. Device GPA 0x{:013x}, next_ram GPA 0x{:013x}",
                    cur_blocked.start, next_ram_gpa);
                        next_ram_gpa += cur_blocked.size();

                        next_blocked = next_blocked_iter.next();

                        //next blocked might by contiguous -> skip over next until there is a gap
                        while let Some(nb) = next_blocked {
                            if nb.start == (cur_blocked.start + cur_blocked.size()) {
                                assert_eq!(
                                    next_ram_gpa, nb.start,
                                    "next_ram_gpa 0x{:013x}, nb.start 0x{:013x}, cur_blocked.start 0x{:013x}, cur_blocked.end 0x{:013x}",
                                    next_ram_gpa, nb.start, cur_blocked.start, cur_blocked.start + cur_blocked.size()
                                );
                                /*critical bugfix here, was + nb.start before. Found this only because the assertion in the previous line failed.
                                Prior to the remapper refactor, we did not get the assert fail although we have been using the same memory layout.
                                 */
                                next_ram_gpa += nb.size();
                                cur_blocked = nb;
                                next_blocked = next_blocked_iter.next();
                            } else {
                                break;
                            }
                        }
                    }
                } // end of "while remaining_chunk_bytes > 0"
                _total_ram_range_count += 1;
            }
            // Device memory must be identity mapped, to pass through the access to the pyhsical HW
            ResourceKind::Device => {
                let dev_start = range.start;
                let dev_end = dev_start + range.size();
                map_cb(
                    HostPhysAddr::new(dev_start),
                    GuestPhysAddr::new(dev_start),
                    range.size(),
                    1,
                )
                .map_err(|e| {
                    log::error!(
                        "failed to map HPA 0x{:013x} at GPA 0x{:013x} for 0x{:x} bytes in remappar",
                        range.start,
                        range.start,
                        range.size()
                    );
                    e
                })?;
                mapping_count += 1;
                highest_device_gpa = Some(GuestPhysAddr::new(match highest_device_gpa {
                    Some(v) => {
                        if v.as_usize() > dev_end {
                            v.as_usize()
                        } else {
                            dev_end
                        }
                    }
                    None => range.start + range.size(),
                }));
            }
        } // end of "match resource_kind"
    }
    Ok((GuestPhysAddr::new(next_ram_gpa), highest_device_gpa))
}

/// Convenience wrapper around [`compactify_colors_in_gpa_space_cb_mapper`] that directly works with
/// the provided `remapper`
pub fn compactify_colors_in_gpa_space<const N: usize, T: MemoryColoring + Clone + Default>(
    remapper: &mut Remapper<N>,
    permission_iter: PermissionIterator<T>,
    start_gpa: GuestPhysAddr,
) -> Result<(GuestPhysAddr, Option<GuestPhysAddr>), CapaError> {
    let mut cb = |hpa: HostPhysAddr, gpa: GuestPhysAddr, size: usize, repeat: usize| {
        remapper.map_range(hpa.as_usize(), gpa.as_usize(), size, repeat)
    };
    compactify_colors_in_gpa_space_cb_mapper(&mut cb, permission_iter, start_gpa)
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {
    use mmu::memory_coloring::color_to_phys::PhysRange;
    use mmu::memory_coloring::{self, ActiveMemoryColoring, MyBitmap};
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
    fn simple_compactify() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();
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
        let (end_ram_gpa, end_device_gpa) = compactify_colors_in_gpa_space(
            &mut remapper,
            tracker.permissions(&pool, coloring.clone(), None, true),
            GuestPhysAddr::new(0),
        )
        .expect("compactify failed");

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
        assert_eq!(
            WANT_END_RAM_GPA,
            end_ram_gpa,
            "RAM, wanted last GPA 0x{:013x}, got last GPA 0x{:013x}",
            WANT_END_RAM_GPA.as_u64(),
            end_ram_gpa.as_u64()
        );
        let end_device_gpa = end_device_gpa.expect("exected Some last device GPA but got None");
        assert_eq!(
            WANT_END_DEVICE_GPA,
            end_device_gpa,
            "Device, wanted last GPA 0x{:013x}, got last GPA 0x{:013x}",
            WANT_END_RAM_GPA.as_u64(),
            end_device_gpa.as_u64()
        );
    }

    #[test]
    fn compactify_with_gap_to_last_device() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();
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
        let (end_ram_gpa, end_device_gpa) = compactify_colors_in_gpa_space(
            &mut remapper,
            tracker.permissions(&pool, coloring.clone(), None, true),
            GuestPhysAddr::new(0),
        )
        .expect("compactify failed");

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
        assert_eq!(
            WANT_END_RAM_GPA,
            end_ram_gpa,
            "RAM, wanted last GPA 0x{:013x}, got last GPA 0x{:013x}",
            WANT_END_RAM_GPA.as_u64(),
            end_ram_gpa.as_u64()
        );
        let end_device_gpa = end_device_gpa.expect("exected Some last device GPA but got None");
        assert_eq!(
            WANT_END_DEVICE_GPA,
            end_device_gpa,
            "Device, wanted last GPA 0x{:013x}, got last GPA 0x{:013x}",
            WANT_END_RAM_GPA.as_u64(),
            end_device_gpa.as_u64()
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
        let mut remapper: Remapper<128> = Remapper::new();
        let coloring = RangeBasedTestColoring::new(vec![
            (
                PhysRange {
                    start: 0x0_000,
                    end: 0x4_000,
                },
                0,
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
        for x in 1..120 {
            tracker
                .add_region(
                    0x8_000 + (x * 0x1_000),
                    0x8_000 + (x * 0x1_000) + 0x1_000,
                    MEMOPS_ALL,
                    ResourceKind::ram_with_all_partitions(),
                    &mut pool,
                )
                .unwrap();
        }

        remapper
            .map_compactified_range((0, 1), true, 0x10_000, tracker.iter(&pool))
            .expect("failed to add compactified mapping");

        /*println!("merged remap iter");
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
            println!("{:x?}", x);
        }*/
    }

    #[test]
    fn remap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();
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
            "{[0x1000, 0x2000 | 1 (1 - 1 - 1 - 1)]}",
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
        snap("{[0x1000, 0x2000 | 1 (1 - 1 - 1 - 1)] -> [0x3000, 0x4000 | 1 (1 - 1 - 1 - 1)] -> [0x4000, 0x5000 | 1 (1 - 0 - 0 - 0)]}", &tracker.iter(&pool));
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
            "{[0x1000, 0x2000 | 1 (1 - 1 - 1 - 1)] -> [0x3000, 0x4000 | 1 (1 - 1 - 1 - 1)]}",
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
        let mut remapper: Remapper<32> = Remapper::new();
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
            "{[0x1000, 0x3000 | 1 (1 - 1 - 1 - 1)] -> [0x4000, 0x6000 | 1 (1 - 1 - 1 - 1)]}",
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
        let mut remapper: Remapper<32> = Remapper::new();
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
            "{[0x1000, 0x3000 | 1 (1 - 1 - 1 - 1)] -> [0x3000, 0x4000 | 2 (2 - 2 - 2 - 2)]}",
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
        let mut remapper: Remapper<32> = Remapper::new();
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
            "{[0x1000, 0x4000 | 1 (1 - 1 - 1 - 1)]}",
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
        let mut remapper: Remapper<32> = Remapper::new();
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
            "{[0x1000, 0x4000 | 1 (1 - 1 - 1 - 1)]}",
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
        let mut remapper: Remapper<32> = Remapper::new();
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
            "{[0x1000, 0x6000 | 1 (1 - 1 - 1 - 1)]}",
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
            "{[0x1000, 0x6000 | 1 (1 - 1 - 1 - 1)]}",
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
        let mut remapper: Remapper<32> = Remapper::new();

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
        snap("{[0x12fcb6000, 0x12fcd6000 | 1 (1 - 1 - 1 - 1)] -> [0x12fcd6000, 0x12fcf6000 | 2 (2 - 2 - 2 - 2)]}", &tracker.iter(&pool));
        snap("{[0x12fcb6000, 0x12fcf6000 at 0xfffc0000, rep 1] -> [0x12fcd6000, 0x12fcf6000 at 0xe0000, rep 1]}", remapper.iter_segments());
    }

    #[test]
    fn gpa_overlap() {
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        let mut tracker = RegionTracker::new();
        let mut remapper: Remapper<32> = Remapper::new();
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
            "{[0x2000, 0x8000 | 1 (1 - 1 - 1 - 1)]}",
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
            "{[0x2000, 0xa000 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );
        let err = remapper.map_range(0x8000, 0x22000, 0x2000, 1);
        assert!(err.is_err());
        assert_eq!(err.err().unwrap(), CapaError::AlreadyAliased);
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
            "{[0x3000, 0x6000 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );
        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool, all_same_color.clone(), None, true),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x1000, 0x10000, 0x1000, 1),
        };
        snap("", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool, all_same_color.clone(), None, true),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x7000, 0x10000, 0x1000, 1),
        };
        snap("", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool, all_same_color.clone(), None, true),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x2000, 0x10000, 0x2000, 1),
        };
        snap("[0x3000, 0x4000 at 0x11000, rep 1 | RWXS]", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool, all_same_color.clone(), None, true),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x5000, 0x10000, 0x2000, 1),
        };
        snap("[0x5000, 0x6000 at 0x10000, rep 1 | RWXS]", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool, all_same_color.clone(), None, true),
            next_region: None,
            cursor: 0,
            segment: dummy_segment(0x4000, 0x10000, 0x1000, 1),
        };
        snap("[0x4000, 0x5000 at 0x10000, rep 1 | RWXS]", iterator);

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool, all_same_color.clone(), None, true),
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
            "{[0x3000, 0x6000 | 1 (1 - 1 - 1 - 1)] -> [0x7000, 0x8000 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        let iterator = SingleSegmentIterator {
            regions: tracker.permissions(&pool, all_same_color.clone(), None, true),
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

impl<'a, const N: usize, T: MemoryColoring + Clone + Default> fmt::Display
    for RemapIterator<'a, N, T>
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
