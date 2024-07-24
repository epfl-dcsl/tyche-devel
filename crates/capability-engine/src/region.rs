use core::fmt;

use bitflags::bitflags;
use mmu::memory_coloring::color_to_phys::{
    ColorToPhys, ColorToPhysIter, MemoryRegionDescription, PhysRange,
};
use mmu::memory_coloring::{
    ActiveMemoryColoring, ColorBitmap, MemoryColoring, MyBitmap, PartitionBitmap,
};

use crate::config::NB_TRACKER;
use crate::gen_arena::{GenArena, Handle};
use crate::CapaError;

bitflags! {
    pub struct MemOps: u8 {
        const NONE  = 0;
        const READ  = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC  = 1 << 2;
        const SUPER = 1 << 3;
        const HASH = 1 << 4; // Flag for do we want to hash particular RegionCapa
        const CLEANUP = 1 << 5;
        const VITAL = 1 << 6;
    }
}

pub const MEMOPS_ALL: MemOps = MemOps::READ
    .union(MemOps::WRITE)
    .union(MemOps::EXEC)
    .union(MemOps::SUPER);

pub const MEMOPS_EXTRAS: MemOps = MemOps::HASH.union(MemOps::CLEANUP).union(MemOps::VITAL);

impl MemOps {
    pub fn from_usize(val: usize) -> Result<Self, CapaError> {
        let value = match Self::from_bits(val as u8) {
            Some(v) => v,
            _ => {
                return Err(CapaError::InvalidMemOps);
            }
        };

        if !value.is_valid() {
            return Err(CapaError::InvalidMemOps);
        }
        return Ok(value);
    }

    pub fn is_valid(&self) -> bool {
        if (self.contains(MemOps::WRITE) || self.contains(MemOps::EXEC))
            & !self.contains(MemOps::READ)
        {
            return false;
        }
        return true;
    }
    pub fn is_only_hcv(&self) -> bool {
        !self.intersects(MEMOPS_ALL)
    }

    pub fn as_counters(&self) -> (usize, usize, usize, usize) {
        let read_count: usize = if self.contains(Self::READ) { 1 } else { 0 };
        let write_count: usize = if self.contains(Self::WRITE) { 1 } else { 0 };
        let exec_count: usize = if self.contains(Self::EXEC) { 1 } else { 0 };
        let super_count: usize = if self.contains(Self::SUPER) { 1 } else { 0 };
        (read_count, write_count, exec_count, super_count)
    }
}

/// Describes the kind of ressource that an access right grants access to
///
#[derive(Clone, Copy, Debug)]
pub enum ResourceKind {
    /// Access to RAM memory, which may be suspect to further sub partitioning
    RAM(PartitionBitmap),
    /// Access to device memory
    Device,
}

impl ResourceKind {
    ///Convenience function that creates a RessourceKind::RAM with all partitions/colors enabled
    pub fn ram_with_all_partitions() -> ResourceKind {
        let mut partitions = PartitionBitmap::new();
        partitions.set_all(true);
        Self::RAM(partitions)
    }

    /// Convenience function that creates a RessourcKind::RAM for the given partitions
    pub fn ram_with_partitions(partition_ids: &[usize]) -> ResourceKind {
        let mut partitions = PartitionBitmap::new();
        for idx in partition_ids {
            partitions.set(*idx, true);
        }
        Self::RAM(partitions)
    }

    /// Returns true if a and b are of the same enum variant. Does not compare the associated data
    pub fn same_kind(a: &ResourceKind, b: &ResourceKind) -> bool {
        match (a, b) {
            (ResourceKind::RAM(_), ResourceKind::RAM(_)) => true,
            (ResourceKind::Device, ResourceKind::Device) => true,
            _ => false,
        }
    }
}

impl From<&RegionResourceKind> for ResourceKind {
    fn from(value: &RegionResourceKind) -> Self {
        match value {
            RegionResourceKind::RAM(refcount) => {
                let bm = refcount.as_partition_bitmap();
                ResourceKind::RAM(bm)
            }
            RegionResourceKind::Device => ResourceKind::Device,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AccessRights {
    pub start: usize,
    pub end: usize,
    pub resource: ResourceKind,
    pub ops: MemOps,
}

impl AccessRights {
    pub fn is_valid(&self) -> bool {
        self.start <= self.end
            && match &self.resource {
                ResourceKind::RAM(partitions) => !partitions.all_bits_unset(),
                ResourceKind::Device => true,
            }
    }

    pub const fn none(resource_kind: ResourceKind) -> Self {
        Self {
            start: 0,
            end: 0,
            resource: resource_kind,
            ops: MemOps::NONE,
        }
    }

    pub fn overlap(&self, other: &AccessRights) -> bool {
        if other.end > self.start && other.start < self.end {
            return true;
        }

        false
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PermissionChange {
    None,
    Some,
}

impl PermissionChange {
    pub fn update(&mut self, other: Self) {
        if let PermissionChange::Some = other {
            *self = PermissionChange::Some;
        }
    }
}

///Refcount for access permission to partitions
///`K` is the partition count
// be careful to not mix up with type parameters from bitmap
#[derive(Debug, Clone, Copy)]
struct PartitionRefCount<const N: usize> {
    data: [usize; N],
}

impl<const K: usize> PartitionRefCount<K> {
    /// Creates new object with all refcounts set to zero
    const fn new() -> Self {
        Self { data: [0_usize; K] }
    }

    /// Increases the refcount for all partitions for which `incoming` contains a 1
    /// Returns the number of partitions whoose refcount increased from 0 to 1 by this update
    fn increase_count<const N: usize>(&mut self, incoming: &MyBitmap<N, K>) -> usize {
        let mut new_nonzero_count = 0;
        for idx in 0..incoming.get_payload_bits_len() {
            if incoming.get(idx) {
                self.data[idx] += 1;
                if self.data[idx] == 1 {
                    new_nonzero_count += 1;
                }
            }
        }
        new_nonzero_count
    }

    /// Decreases the refcount for all partitions that are set in `leaving`
    /// If this changes the refcount of any currently nonzero value to zero
    /// Returns the number of partitions whoose refcount dropped to zero by this update
    fn decrease_refcount<const N: usize>(&mut self, leaving: &MyBitmap<N, K>) -> usize {
        let mut dropped_to_zero_count = 0;
        for idx in 0..leaving.get_payload_bits_len() {
            if leaving.get(idx) {
                self.data[idx].checked_sub(1).unwrap();
                if self.data[idx] == 0 {
                    dropped_to_zero_count += 1;
                }
            }
        }
        dropped_to_zero_count
    }

    /// Creates a new partition bitmap where an entry is set to true
    /// if its refcount is > 0
    pub fn as_partition_bitmap<const N: usize>(&self) -> MyBitmap<N, K> {
        let mut bm = MyBitmap::new();

        for idx in 0..K {
            if self.data[idx] > 0 {
                bm.set(idx, true);
            }
        }

        bm
    }
}

impl<const K: usize> PartialEq for PartitionRefCount<K> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<const N: usize, const K: usize> From<&MyBitmap<N, K>> for PartitionRefCount<K> {
    fn from(value: &MyBitmap<N, K>) -> Self {
        let mut refcount: PartitionRefCount<K> = PartitionRefCount::<{ K }>::new();
        refcount.increase_count(value);
        refcount
    }
}

// ———————————————————————————————— Regions ————————————————————————————————— //

///Like `ResourceKind` but we need a different associated type here, to keep a refcount instead of
/// just a bitmap. Changing the other type would add some memory overhead, as we only need
/// the refcount information here
#[derive(Debug, Clone, Copy)]
enum RegionResourceKind {
    RAM(PartitionRefCount<{ ActiveMemoryColoring::COLOR_COUNT }>),
    Device,
}

impl RegionResourceKind {
    /// Convenience function to create a RAM resource with all zero refcount
    #[allow(dead_code)]
    const fn new_ram() -> RegionResourceKind {
        RegionResourceKind::RAM(PartitionRefCount::<{ ActiveMemoryColoring::COLOR_COUNT }>::new())
    }

    /// Returns true `other` can be used to update this resource kind
    fn is_compatible(&self, other: &ResourceKind) -> bool {
        match (self, other) {
            (RegionResourceKind::RAM(_), ResourceKind::RAM(_)) => true,
            (RegionResourceKind::Device, ResourceKind::Device) => true,
            _ => false,
        }
    }
}

impl From<&ResourceKind> for RegionResourceKind {
    fn from(value: &ResourceKind) -> Self {
        match value {
            ResourceKind::RAM(partition_bitmap) => RegionResourceKind::RAM(partition_bitmap.into()),
            ResourceKind::Device => RegionResourceKind::Device,
        }
    }
}

pub(crate) type TrackerPool = GenArena<Region, NB_TRACKER>;

pub(crate) const EMPTY_REGION: Region = Region {
    start: 0,
    end: 0,
    read_count: 0,
    write_count: 0,
    exec_count: 0,
    super_count: 0,
    ref_count: 0,
    next: None,
    resource_kind: RegionResourceKind::Device,
};

#[derive(Debug)]
pub struct Region {
    start: usize,
    end: usize,
    read_count: usize,
    write_count: usize,
    exec_count: usize,
    super_count: usize,
    resource_kind: RegionResourceKind,
    ref_count: usize,
    next: Option<Handle<Region>>,
}

impl Region {
    fn new(start: usize, end: usize, ops: MemOps, resource_kind: &ResourceKind) -> Self {
        if start >= end {
            log::error!(
                "Region start must be smaller than end, got start = {} and end = {}",
                start,
                end
            );
            panic!("Invalid region");
        }
        let (r, w, x, s) = ops.as_counters();
        Self {
            start,
            end,
            read_count: r,
            write_count: w,
            exec_count: x,
            super_count: s,
            resource_kind: resource_kind.into(),
            ref_count: 1,
            next: None,
        }
    }

    fn set_next(mut self, next: Option<Handle<Region>>) -> Self {
        self.next = next;
        self
    }

    pub fn contains(&self, addr: usize) -> bool {
        self.start <= addr && addr < self.end
    }

    /// Returns true if read,write,exec,super and partition id refcounts are equal
    pub fn same_counts(&self, other: &Self) -> bool {
        self.ref_count == other.ref_count
            && self.read_count == other.read_count
            && self.write_count == other.write_count
            && self.exec_count == other.exec_count
            && self.super_count == other.super_count
            && match (self.resource_kind, other.resource_kind) {
                (RegionResourceKind::RAM(ours), RegionResourceKind::RAM(others)) => ours == others,
                (RegionResourceKind::Device, RegionResourceKind::Device) => true,
                _ => false,
            }
    }

    pub fn get_ops(&self) -> MemOps {
        let mut ops = MemOps::NONE;
        if self.read_count > 0 {
            ops |= MemOps::READ;
        }
        if self.write_count > 0 {
            ops |= MemOps::WRITE;
        }
        if self.exec_count > 0 {
            ops |= MemOps::EXEC;
        }
        if self.super_count > 0 {
            ops |= MemOps::SUPER;
        }
        ops
    }

    pub fn get_start(&self) -> usize {
        self.start
    }

    pub fn get_end(&self) -> usize {
        self.end
    }
}

// ————————————————————————————— RegionTracker —————————————————————————————— //

pub struct RegionTracker {
    head: Option<Handle<Region>>,
}

impl RegionTracker {
    pub const fn new() -> Self {
        Self { head: None }
    }

    pub fn get_refcount(&self, start: usize, end: usize, tracker: &TrackerPool) -> usize {
        let mut count = 0;

        for (_, region) in self.iter(tracker) {
            if region.end <= start {
                continue;
            } else if region.start >= end {
                break;
            } else {
                count = core::cmp::max(count, region.ref_count)
            }
        }

        count
    }

    pub fn remove_region(
        &mut self,
        start: usize,
        end: usize,
        ops: MemOps,
        resource_kind: ResourceKind,
        tracker: &mut TrackerPool,
    ) -> Result<PermissionChange, CapaError> {
        log::trace!("Removing region [0x{:x}, 0x{:x}]", start, end);

        assert!(start <= end);
        if start == end {
            // Empty region: nothing to do
            return Ok(PermissionChange::None);
        }

        let (Some(mut bound), mut prev) = self.find_lower_bound(start, tracker) else {
            log::trace!("Region does not exist");
            return Err(CapaError::InvalidRegion);
        };

        // Check if we need a split for the start.
        if tracker[bound].start < start {
            prev = Some(bound);
            bound = self.split_region_at(bound, start, tracker)?;
        }
        // Check if we need a split for the end.
        if tracker[bound].end > end {
            let _ = self.split_region_at(bound, end, tracker)?;
        }

        assert_eq!(
            tracker[bound].start, start,
            "Remove region must specify exact boundaries"
        );

        let mut change = PermissionChange::None;
        let mut next = bound;
        while tracker[next].start < end {
            let mut update = self.decrease_refcount(next, tracker);
            update.update(self.decrease_ops(next, ops, resource_kind, tracker)?);
            change.update(update);

            // Free regions with ref_count 0.
            if tracker[next].ref_count == 0 {
                // Remove the element from the list.
                let to_visit = tracker[next].next;
                match prev {
                    Some(handle) => {
                        tracker[handle].next = tracker[next].next;
                    }
                    None => {
                        self.head = tracker[next].next;
                    }
                }
                // Free the region.
                tracker.free(next);

                // Update next.
                match to_visit {
                    Some(handle) => {
                        next = handle;
                        continue;
                    }
                    None => {
                        break;
                    }
                }
                // End of free block.
            }

            match &tracker[next].next {
                Some(handle) => {
                    prev = Some(next);
                    next = *handle;
                }
                None => {
                    break;
                }
            }
        }

        // coalesce.
        self.coalesce(tracker);
        Ok(change)
    }

    pub fn add_region(
        &mut self,
        start: usize,
        end: usize,
        ops: MemOps,
        resource_kind: ResourceKind,
        tracker: &mut TrackerPool,
    ) -> Result<PermissionChange, CapaError> {
        log::trace!("Adding region [0x{:x}, 0x{:x}]", start, end);

        assert!(start <= end);
        if start == end {
            // return immediately, nothing to do
            return Ok(PermissionChange::None);
        }

        // There is no region yet, insert head and exit
        let Some(head) = self.head else {
            self.insert_head(start, end, ops, resource_kind, tracker)?;
            return Ok(PermissionChange::Some);
        };

        let mut change = PermissionChange::None;
        let (mut previous, mut cursor) =
            if let (Some(lower_bound), _) = self.find_lower_bound(start, tracker) {
                let region = &tracker[lower_bound];
                if start == region.start {
                    // Regions have the same start
                    let (previous, update) = self.partial_add_region_overlapping(
                        start,
                        end,
                        lower_bound,
                        ops,
                        resource_kind,
                        tracker,
                    )?;
                    change.update(update);
                    let cursor = tracker[previous].end;
                    (previous, cursor)
                } else if region.contains(start) {
                    // Region start in the middle of the lower bound region
                    self.split_region_at(lower_bound, start, tracker)?;
                    (lower_bound, start)
                } else {
                    // Region starts after lower bound region
                    (lower_bound, start)
                }
            } else {
                let head = &tracker[head];
                let cursor = core::cmp::min(end, head.start);
                let previous = self.insert_head(start, cursor, ops, resource_kind, tracker)?;
                change = PermissionChange::Some;
                (previous, cursor)
            };

        // Add the remaining portions of the region
        while cursor < end {
            let (next, update) =
                self.partial_add_region_after(cursor, end, previous, ops, resource_kind, tracker)?;
            previous = next;
            change.update(update);
            cursor = tracker[previous].end;
        }

        // Coalesce.
        self.coalesce(tracker);
        Ok(change)
    }

    fn partial_add_region_after(
        &mut self,
        start: usize,
        end: usize,
        after: Handle<Region>,
        ops: MemOps,
        resource_kind: ResourceKind,
        tracker: &mut TrackerPool,
    ) -> Result<(Handle<Region>, PermissionChange), CapaError> {
        let region = &mut tracker[after];

        assert!(start < end, "Tried to add invalid region");
        assert!(region.end <= start, "Invalid add_region_after");

        // Check how much of the region can fit before the next one
        let mut end = end;
        if let Some(next_handle) = region.next {
            let next = &mut tracker[next_handle];
            if start == next.start {
                // Overlapping
                return self.partial_add_region_overlapping(
                    start,
                    end,
                    next_handle,
                    ops,
                    resource_kind,
                    tracker,
                );
            } else if end > next.start {
                // Fit as much as possible
                end = next.start;
            }
        }
        self.insert_after(start, end, ops, resource_kind, after, tracker)
    }

    fn partial_add_region_overlapping(
        &mut self,
        start: usize,
        end: usize,
        overlapping: Handle<Region>,
        ops: MemOps,
        resource_kind: ResourceKind,
        tracker: &mut TrackerPool,
    ) -> Result<(Handle<Region>, PermissionChange), CapaError> {
        let region = &tracker[overlapping];
        assert!(
            region.start == start,
            "Region is not overlapping from the start"
        );

        if end < region.end {
            self.split_region_at(overlapping, end, tracker)?;
        }
        let mut change = self.increase_refcount(overlapping, tracker);
        change.update(self.increase_ops(overlapping, ops, resource_kind, tracker)?);
        Ok((overlapping, change))
    }

    /// Returns a handle to the region with the closest (inferior or equal) start address.
    /// First value is the closest, second is the previous element.
    fn find_lower_bound(
        &self,
        start: usize,
        tracker: &mut TrackerPool,
    ) -> (Option<Handle<Region>>, Option<Handle<Region>>) {
        let Some(mut closest) = self.head else {
            return (None, None);
        };

        if tracker[closest].start > start {
            // The first region already starts at a higher address
            return (None, None);
        }
        let mut prev = None;
        let mut iter = None;
        for (handle, region) in self.iter(tracker) {
            if region.start <= start {
                prev = iter;
                closest = handle
            } else {
                break;
            }
            iter = Some(handle);
        }

        (Some(closest), prev)
    }

    /// Split the given region at the provided address. Returns a handle to the second half (the
    /// first hald keeps the same handle).
    fn split_region_at(
        &mut self,
        handle: Handle<Region>,
        at: usize,
        tracker: &mut TrackerPool,
    ) -> Result<Handle<Region>, CapaError> {
        let region = &tracker[handle];
        assert!(
            region.contains(at),
            "Tried to split at an address that is not contained in the region"
        );

        // Allocate the second half
        let second_half = Region {
            start: at,
            end: region.end,
            read_count: region.read_count,
            write_count: region.write_count,
            exec_count: region.exec_count,
            super_count: region.super_count,
            ref_count: region.ref_count,
            next: region.next,
            resource_kind: region.resource_kind,
        };
        let second_half_handle = tracker.allocate(second_half).ok_or_else(|| {
            log::error!("Unable to allocate new region!");
            CapaError::OutOfMemory
        })?;

        // Update the first half
        let region = &mut tracker[handle];
        region.end = at;
        region.next = Some(second_half_handle);

        Ok(second_half_handle)
    }

    /// Insert a fresh region after the region pointer by the `after` handle. Returns a handle
    /// to the inserted region.
    fn insert_after(
        &mut self,
        start: usize,
        end: usize,
        ops: MemOps,
        resource_kind: ResourceKind,
        after: Handle<Region>,
        tracker: &mut TrackerPool,
    ) -> Result<(Handle<Region>, PermissionChange), CapaError> {
        let region = &tracker[after];
        assert!(start >= region.end, "Regions should be sorted by addresses");
        if let Some(next) = region.next {
            assert!(
                end <= tracker[next].start,
                "Regions should be sorted by addresses"
            );
        }

        let handle = tracker
            .allocate(Region::new(start, end, ops, &resource_kind).set_next(region.next))
            .ok_or_else(|| {
                log::trace!("Unable to allocate new region!");
                CapaError::OutOfMemory
            })?;
        let region = &mut tracker[after];
        region.next = Some(handle);

        // There is alway a permission change in this case
        Ok((handle, PermissionChange::Some))
    }

    fn insert_head(
        &mut self,
        start: usize,
        end: usize,
        ops: MemOps,
        resource_kind: ResourceKind,
        tracker: &mut TrackerPool,
    ) -> Result<Handle<Region>, CapaError> {
        if let Some(head) = self.head {
            assert!(
                tracker[head].start >= end,
                "Region should be sorted by address"
            );
        }

        let region = Region::new(start, end, ops, &resource_kind).set_next(self.head);
        let handle = tracker.allocate(region).ok_or_else(|| {
            log::trace!("Unable to allocate new region!");
            CapaError::OutOfMemory
        })?;
        self.head = Some(handle);
        Ok(handle)
    }

    fn increase_refcount(
        &mut self,
        handle: Handle<Region>,
        tracker: &mut TrackerPool,
    ) -> PermissionChange {
        let region = &mut tracker[handle];
        region.ref_count += 1;

        if region.ref_count == 1 {
            PermissionChange::Some
        } else {
            PermissionChange::None
        }
    }

    fn increase_ops(
        &mut self,
        handle: Handle<Region>,
        ops: MemOps,
        resource_kind: ResourceKind,
        tracker: &mut TrackerPool,
    ) -> Result<PermissionChange, CapaError> {
        let region = &mut tracker[handle];
        let mut change = PermissionChange::None;
        if ops.contains(MemOps::READ) {
            region.read_count += 1;
            if region.read_count == 1 {
                change = PermissionChange::Some;
            }
        }
        if ops.contains(MemOps::WRITE) {
            region.write_count += 1;
            if region.write_count == 1 {
                change = PermissionChange::Some;
            }
        }
        if ops.contains(MemOps::EXEC) {
            region.exec_count += 1;
            if region.exec_count == 1 {
                change = PermissionChange::Some;
            }
        }
        if ops.contains(MemOps::SUPER) {
            region.super_count += 1;
            if region.super_count == 1 {
                change = PermissionChange::Some;
            }
        }

        if !region.resource_kind.is_compatible(&resource_kind) {
            return Err(CapaError::CapaOperationOnDifferentResourceKinds);
        }

        match (region.resource_kind, resource_kind) {
            (RegionResourceKind::RAM(mut refcount), ResourceKind::RAM(incoming_partitions)) => {
                if refcount.increase_count(&incoming_partitions) > 0 {
                    change = PermissionChange::Some
                }
            }
            _ => (),
        };

        return Ok(change);
    }

    fn decrease_refcount(
        &mut self,
        handle: Handle<Region>,
        tracker: &mut TrackerPool,
    ) -> PermissionChange {
        let region = &mut tracker[handle];
        region.ref_count = region.ref_count.checked_sub(1).unwrap();

        if region.ref_count == 0 {
            PermissionChange::Some
        } else {
            PermissionChange::None
        }
    }

    fn decrease_ops(
        &mut self,
        handle: Handle<Region>,
        ops: MemOps,
        resource_kind: ResourceKind,
        tracker: &mut TrackerPool,
    ) -> Result<PermissionChange, CapaError> {
        let region = &mut tracker[handle];
        let mut change = PermissionChange::None;
        if ops.contains(MemOps::READ) {
            region.read_count = region.read_count.checked_sub(1).unwrap();
            if region.read_count == 0 {
                change = PermissionChange::Some;
            }
        }
        if ops.contains(MemOps::WRITE) {
            region.write_count = region.write_count.checked_sub(1).unwrap();
            if region.write_count == 0 {
                change = PermissionChange::Some;
            }
        }
        if ops.contains(MemOps::EXEC) {
            region.exec_count = region.exec_count.checked_sub(1).unwrap();
            if region.exec_count == 0 {
                change = PermissionChange::Some;
            }
        }
        if ops.contains(MemOps::SUPER) {
            region.super_count = region.super_count.checked_sub(1).unwrap();
            if region.super_count == 0 {
                change = PermissionChange::Some;
            }
        }

        if !region.resource_kind.is_compatible(&resource_kind) {
            return Err(CapaError::CapaOperationOnDifferentResourceKinds);
        }

        match (region.resource_kind, resource_kind) {
            (RegionResourceKind::RAM(mut refcount), ResourceKind::RAM(leaving_partitions)) => {
                if refcount.decrease_refcount(&leaving_partitions) > 0 {
                    change = PermissionChange::Some;
                }
            }
            _ => (),
        };

        return Ok(change);
    }

    /// This will try to merge adjacent regions and drop empty regions
    fn coalesce(&mut self, tracker: &mut TrackerPool) {
        if self.head == None {
            // Nothing to do.
            return;
        }
        let mut prev = self.head.unwrap();
        let mut curr = tracker[prev].next;

        // Go through the list.
        while curr != None {
            let current = curr.unwrap();
            /*
               Case 1: adjacent regions with same refcounts for permissions + colors
               Case 2: Current region is empty
               Case 3: prev region is empty
            */
            if tracker[prev].end == tracker[current].start
                && (tracker[prev].same_counts(&tracker[current])
                    || tracker[current].start == tracker[current].end
                    || tracker[prev].start == tracker[prev].end)
            {
                // Coalesce: Copy "current" into "prev" and free object for current
                if tracker[prev].start == tracker[prev].end {
                    tracker[prev].ref_count = tracker[current].ref_count;
                }
                tracker[prev].next = tracker[current].next;
                tracker[prev].end = tracker[current].end;
                tracker.free(curr.unwrap());
                curr = tracker[prev].next;
                continue;
            }
            prev = curr.unwrap();
            curr = tracker[current].next;
        }
    }

    pub fn iter<'a>(&'a self, pool: &'a TrackerPool) -> RegionIterator<'a> {
        RegionIterator {
            pool,
            next: self.head,
        }
    }

    pub fn iter_from<'a>(
        &'a self,
        start: Option<Handle<Region>>,
        pool: &'a TrackerPool,
    ) -> RegionIterator<'a> {
        RegionIterator { pool, next: start }
    }

    /// Transform granted CAPAs into deduplicated ranges of accessible
    /// HPA ranges
    /// # Arguments
    /// - `additional_color_restrictions`: If Some, restrict allowed colors to only these. Must be
    /// a subset of the colors granted in the CAPAs. Useful to distingiush between "core" memory and "future TD" memory
    /// - `allow_devices` : If false, exclude device memory ranges
    pub fn permissions<'a, T: MemoryColoring + Clone>(
        &'a self,
        pool: &'a TrackerPool,
        memory_coloring: T,
        additional_color_restrictions: Option<PartitionBitmap>,
        allow_devices: bool,
    ) -> PermissionIterator<'a, T> {
        PermissionIterator {
            tracker: self,
            pool,
            next: self.head,
            memory_coloring,
            current_subranges: None,
            additional_color_restrictions,
            allow_devices,
        }
    }
}

// ———————————————————————————— Region Iterators ———————————————————————————— //

#[derive(Clone)]
pub struct RegionIterator<'a> {
    pool: &'a TrackerPool,
    next: Option<Handle<Region>>,
}

impl<'a> Iterator for RegionIterator<'a> {
    type Item = (Handle<Region>, &'a Region);

    fn next(&mut self) -> Option<Self::Item> {
        let handle = self.next?;
        let region = &self.pool[handle];

        self.next = region.next;
        Some((handle, region))
    }
}

/// An iterator over a domain's memory access permissions. They are created based
/// on the domains memory regions
#[derive(Clone)]
pub struct PermissionIterator<'a, T: MemoryColoring + Clone> {
    tracker: &'a RegionTracker,
    pool: &'a TrackerPool,
    next: Option<Handle<Region>>,
    memory_coloring: T,
    //If Some, we are still processing the colored subranges from the current region
    current_subranges: Option<(ColorToPhysIter<T>, MemOps, ResourceKind)>,
    //further restrict the colors that we use from the ranges
    additional_color_restrictions: Option<PartitionBitmap>,
    //If false, don't use device memory
    allow_devices: bool,
}

#[derive(Clone, Copy)]
pub struct MemoryPermission {
    pub start: usize,
    pub end: usize,
    pub resource_kind: ResourceKind,
    pub ops: MemOps,
}

impl MemoryPermission {
    pub fn size(&self) -> usize {
        self.end - self.start
    }
}

impl<'a, T: MemoryColoring + Clone> Iterator for PermissionIterator<'a, T> {
    type Item = MemoryPermission;

    //luca: region tracker is a linked list over regions. Regions are a deduplicated view of all resources that are described
    //by the access rights
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            //finish current colored subrange, before moving to next region
            if let Some((colored_subrange, ops, kind)) = &mut self.current_subranges {
                match colored_subrange.next() {
                    Some(v) => {
                        return Some(MemoryPermission {
                            start: v.start,
                            end: v.end,
                            //TODO: this is probably no longer needed in the MemoryPermissions struct
                            resource_kind: *kind,
                            ops: *ops,
                        });
                    }
                    //finished region -> move to next
                    None => {
                        self.current_subranges = None;
                    }
                }
            }

            // Get the first valid region
            let mut handle = None;
            let mut start = None;
            for (h, region) in self.tracker.iter_from(self.next, self.pool) {
                if region.ref_count > 0 {
                    handle = Some(h);
                    start = Some(region.start);
                    break;
                }
            }

            let Some(start) = start else {
                self.next = None; // makes next iteration faster
                return None;
            };
            let (end, ops, resource_kind) = {
                let reg = &self.pool[handle.unwrap()];
                (reg.end, reg.get_ops(), (&reg.resource_kind).into())
            };

            let mut next = None;
            for (handle, _region) in self.tracker.iter_from(handle, self.pool).skip(1) {
                //TODO(aghosn) charly had some optimization here that I had to remove.
                //We can put something correct here in the future.
                next = Some(handle);
                break;
            }

            self.next = next;

            match resource_kind {
                //RAM memory is subject to coloring, iterate over sub ranges create by the coloring before moving to the next region
                ResourceKind::RAM(allowed_colors) => {
                    /* Akward type conversion :( . For testing, we want memory coloring to be configurable and
                     * Thus encode in in generic param. However, using the generic in the widely used type ResourceKind would
                     * mean that it spreads everywhere making the codebase akward to use. Thus we also have a global constant with
                     * The "currently active memory coloring". Here, we need to convert between these two types
                     */
                    let mut bm = T::Bitmap::new_nonconst();
                    let need_dimensions = allowed_colors.dimensions();
                    let have_dimensions = bm.dimensions();
                    assert!(
                        have_dimensions.0 >= need_dimensions.0,
                        "Our bitmap has {} bytes but we need {} bytes",
                        have_dimensions.0,
                        need_dimensions.0
                    );
                    assert!(
                        have_dimensions.1 >= need_dimensions.1,
                        "Our bitmap can represent {} things we need to to represent {} things",
                        have_dimensions.1,
                        need_dimensions.1
                    );
                    for idx in 0..allowed_colors.get_payload_bits_len() {
                        let allowed_in_capa = allowed_colors.get(idx);
                        let allowed_in_add_restrict = match self.additional_color_restrictions {
                            Some(v) => v.get(idx),
                            None => true,
                        };
                        bm.set(idx, allowed_in_capa && allowed_in_add_restrict);
                    }

                    let ctp = ColorToPhys::new(
                        MemoryRegionDescription::SingleRange(PhysRange { start, end }),
                        self.memory_coloring.clone(),
                        bm,
                        None,
                    );
                    let mut iter = ctp.into_iter();
                    match iter.next() {
                        Some(v) => {
                            self.current_subranges = Some((iter, ops, resource_kind));
                            return Some(MemoryPermission {
                                start: v.start,
                                end: v.end,
                                resource_kind,
                                ops,
                            });
                        }
                        //region does not contain any entries with correct color
                        //we will "fall trhough" to the next iteration of the outer loop and continue
                        //with the next region
                        None => {
                            log::warn!("Warning: Empty Region: [0x{:013x}-0x{:013x}[, does not have any subranges with color {:x?}", start,end, allowed_colors);
                            self.current_subranges = None;
                        }
                    }
                }
                //Device mem is not subject to coloring, simply return range
                ResourceKind::Device => {
                    if self.allow_devices {
                        return Some(MemoryPermission {
                            start,
                            end,
                            ops,
                            resource_kind,
                        });
                    }
                }
            }
        }
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {
    use mmu::memory_coloring::color_to_phys::PhysRange;
    use mmu::memory_coloring::{self};
    use utils::HostPhysAddr;

    use super::*;
    use crate::debug::snap;

    #[derive(Clone)]
    struct RangeBasedTestColoring {
        //tuples of phys range with the corresponding color
        ranges: Vec<(PhysRange, u64)>,
    }

    impl RangeBasedTestColoring {
        pub fn new_contig(ranges: Vec<PhysRange>) -> Self {
            let mut tuples = Vec::new();
            for (color_id, range) in ranges.iter().enumerate() {
                tuples.push((*range, color_id as u64))
            }
            Self { ranges: tuples }
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
    }

    #[test]
    fn region() {
        let region = Region {
            start: 0x100,
            end: 0x200,
            read_count: 0,
            write_count: 0,
            exec_count: 0,
            super_count: 0,
            ref_count: 0,
            next: None,
            resource_kind: RegionResourceKind::new_ram(),
        };

        assert!(region.contains(0x100));
        assert!(region.contains(0x150));
        assert!(!region.contains(0x50));
        assert!(!region.contains(0x200));
        assert!(!region.contains(0x250));
    }

    #[test]
    fn region_pool() {
        let mut tracker = RegionTracker::new();
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        tracker
            .add_region(
                0x100,
                0x1000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();

        // Should return None if there is no lower bound region
        assert_eq!(tracker.find_lower_bound(0x50, &mut pool), (None, None));

        let head = tracker.head;
        assert_eq!(tracker.find_lower_bound(0x100, &mut pool), (head, None));
        assert_eq!(tracker.find_lower_bound(0x200, &mut pool), (head, None));
    }

    #[test]
    fn color_filtering() {
        let mut tracker = RegionTracker::new();
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);

        let coloring = RangeBasedTestColoring::new_contig(vec![
            PhysRange {
                start: 0x0,
                end: 0x1_000,
            },
            PhysRange {
                start: 0x1_000,
                end: 0x2_000,
            },
            PhysRange {
                start: 0x2_000,
                end: 0x3_000,
            },
        ]);
        let mut allowed_colors: <RangeBasedTestColoring as MemoryColoring>::Bitmap =
            MyBitmap::new();
        allowed_colors.set(0, true);

        tracker
            .add_region(
                0x0_000,
                0x2_000,
                MEMOPS_ALL,
                ResourceKind::ram_with_partitions(&[0, 2]),
                &mut pool,
            )
            .unwrap();

        tracker
            .add_region(
                0x2_000,
                0x3_000,
                MEMOPS_ALL,
                ResourceKind::ram_with_partitions(&[0, 2]),
                &mut pool,
            )
            .unwrap();
        //Only sub range with colors 0 and 2 is returned, 0x1_000 - 0x2_000
        snap(
            "{[0x0, 0x1000 | RWXS] -> [0x2000, 0x3000 | RWXS]}",
            tracker.permissions(&pool, coloring, None, true),
        );
    }

    #[test]
    fn region_add_no_subpartitions() {
        // Region is added as head
        let mut tracker = RegionTracker::new();
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        tracker
            .add_region(
                0x300,
                0x400,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(
                0x100,
                0x200,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        // Region is added as head, but overlap
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(
                0x200,
                0x400,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x200, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(
                0x100,
                0x300,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x300 | 2 (2 - 2 - 2 - 2)] -> [0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        // Region is completely included
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(
                0x100,
                0x400,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x100, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(
                0x200,
                0x300,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x300 | 2 (2 - 2 - 2 - 2)] -> [0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        // Region is bridging two existing one
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(
                0x100,
                0x400,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x100, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(
                0x500,
                0x1000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x100, 0x400 | 1 (1 - 1 - 1 - 1)] -> [0x500, 0x1000 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );
        tracker
            .add_region(
                0x200,
                0x600,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x400 | 2 (2 - 2 - 2 - 2)] -> [0x400, 0x500 | 1 (1 - 1 - 1 - 1)] -> [0x500, 0x600 | 2 (2 - 2 - 2 - 2)] -> [0x600, 0x1000 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));

        // Region is overlapping two adjacent regions
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(
                0x200,
                0x300,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x200, 0x300 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(
                0x300,
                0x400,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x200, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(
                0x100,
                0x500,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x400 | 2 (2 - 2 - 2 - 2)] -> [0x400, 0x500 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        // Region is added twice
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(
                0x100,
                0x200,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(
                0x100,
                0x200,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x100, 0x200 | 2 (2 - 2 - 2 - 2)]}", &tracker.iter(&pool));

        // Regions have the same end
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(
                0x200,
                0x300,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x200, 0x300 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(
                0x100,
                0x300,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x300 | 2 (2 - 2 - 2 - 2)]}",
            &tracker.iter(&pool),
        );
    }

    //TODO: continue here once basic dom0 ept construction works
    /*#[test]
    fn region_add_with_subpartitions() {
        // Region is added as head
        let mut tracker = RegionTracker::new();
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        tracker
            .add_region(
                0x300,
                0x400,
                MEMOPS_ALL,
                ResourceKind::ram_with_partitions(&[0, 1]),
                &mut pool,
            )
            .unwrap();
        snap("{[0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(
                0x300,
                0x400,
                MEMOPS_ALL,
                ResourceKind::ram_with_partitions(&[2, 3]),
                &mut pool,
            )
            .unwrap();
        snap(
            "{[0x300, 0x400 | 1 (1 - 1 - 1 - 1)] -> [0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );
    }*/

    #[test]
    fn refcount() {
        let mut tracler = RegionTracker::new();
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        tracler
            .add_region(
                0x100,
                0x300,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        tracler
            .add_region(
                0x600,
                0x1000,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        tracler
            .add_region(
                0x200,
                0x400,
                MEMOPS_ALL,
                ResourceKind::ram_with_all_partitions(),
                &mut pool,
            )
            .unwrap();
        snap("{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x300 | 2 (2 - 2 - 2 - 2)] -> [0x300, 0x400 | 1 (1 - 1 - 1 - 1)] -> [0x600, 0x1000 | 1 (1 - 1 - 1 - 1)]}", &tracler.iter(&pool));

        assert_eq!(tracler.get_refcount(0x0, 0x50, &pool), 0);
        assert_eq!(tracler.get_refcount(0x0, 0x100, &pool), 0);
        assert_eq!(tracler.get_refcount(0x0, 0x150, &pool), 1);
        assert_eq!(tracler.get_refcount(0x100, 0x200, &pool), 1);
        assert_eq!(tracler.get_refcount(0x100, 0x250, &pool), 2);
        assert_eq!(tracler.get_refcount(0x0, 0x250, &pool), 2);
        assert_eq!(tracler.get_refcount(0x100, 0x400, &pool), 2);
        assert_eq!(tracler.get_refcount(0x100, 0x500, &pool), 2);
        assert_eq!(tracler.get_refcount(0x400, 0x500, &pool), 0);
        assert_eq!(tracler.get_refcount(0x450, 0x500, &pool), 0);
        assert_eq!(tracler.get_refcount(0x400, 0x2000, &pool), 1);
        assert_eq!(tracler.get_refcount(0x1500, 0x2000, &pool), 0);
    }

    fn dummy_access(start: usize, end: usize) -> AccessRights {
        AccessRights {
            start,
            end,
            resource: ResourceKind::ram_with_all_partitions(),
            ops: MEMOPS_ALL,
        }
    }

    #[test]
    fn overlap() {
        let access = dummy_access(10, 20);

        assert!(access.overlap(&dummy_access(5, 15)));
        assert!(access.overlap(&dummy_access(12, 18)));
        assert!(access.overlap(&dummy_access(15, 25)));
        assert!(access.overlap(&dummy_access(10, 20)));
        assert!(access.overlap(&dummy_access(5, 25)));

        assert!(!access.overlap(&dummy_access(2, 8)));
        assert!(!access.overlap(&dummy_access(22, 28)));
        assert!(!access.overlap(&dummy_access(2, 10)));
        assert!(!access.overlap(&dummy_access(20, 28)));
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl fmt::Display for AccessRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[0x{:x}, 0x{:x} | {}]", self.start, self.end, self.ops)
    }
}

impl<'a> fmt::Display for RegionIterator<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{")?;
        for (_, region) in self.clone() {
            write!(
                f,
                "[0x{:x}, 0x{:x} | {} ({} - {} - {} - {})]",
                region.start,
                region.end,
                region.ref_count,
                region.read_count,
                region.write_count,
                region.exec_count,
                region.super_count
            )?;
            if region.next.is_some() {
                write!(f, " -> ")?;
            }
        }
        write!(f, "}}")
    }
}

impl<'a, T: MemoryColoring + Clone> fmt::Display for PermissionIterator<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut is_first = true;
        write!(f, "{{")?;
        for permission in self.clone() {
            if !is_first {
                write!(f, " -> ")?;
            } else {
                is_first = false;
            }
            write!(f, "{}", permission)?;
        }
        write!(f, "}}")
    }
}

impl fmt::Display for MemoryPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[0x{:x}, 0x{:x} | {}]", self.start, self.end, self.ops)
    }
}

impl fmt::Display for MemOps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.contains(Self::READ) {
            write!(f, "R")?;
        } else {
            write!(f, "_")?;
        }
        if self.contains(Self::WRITE) {
            write!(f, "W")?;
        } else {
            write!(f, "_")?;
        }
        if self.contains(Self::EXEC) {
            write!(f, "X")?;
        } else {
            write!(f, "_")?;
        }
        if self.contains(Self::SUPER) {
            write!(f, "S")?;
        } else {
            write!(f, "_")?;
        }
        write!(f, "")
    }
}
