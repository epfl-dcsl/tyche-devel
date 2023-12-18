use core::fmt;

use bitflags::bitflags;

use crate::config::NB_TRACKER;
use crate::gen_arena::{Cleanable, GenArena, Handle};
use crate::CapaError;

bitflags! {
    pub struct MemOps: u8 {
         const NONE  = 0;
         const READ  = 1 << 0;
         const WRITE = 1 << 1;
         const EXEC  = 1 << 2;
         const SUPER = 1 << 3;
         const HASH = 1 << 4; //flag for do we want to hash particular RegionCapa
    }
}

pub const MEMOPS_ALL: MemOps = MemOps::READ
    .union(MemOps::WRITE)
    .union(MemOps::EXEC)
    .union(MemOps::SUPER)
    .union(MemOps::HASH);

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

    pub fn as_counters(&self) -> (usize, usize, usize, usize) {
        let read_count: usize = if self.contains(Self::READ) { 1 } else { 0 };
        let write_count: usize = if self.contains(Self::WRITE) { 1 } else { 0 };
        let exec_count: usize = if self.contains(Self::EXEC) { 1 } else { 0 };
        let super_count: usize = if self.contains(Self::SUPER) { 1 } else { 0 };
        (read_count, write_count, exec_count, super_count)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AccessRights {
    pub start: usize,
    pub end: usize,
    pub ops: MemOps,
}

impl AccessRights {
    pub fn is_valid(&self) -> bool {
        self.start <= self.end
    }
}

#[derive(Clone, Copy)]
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

// ———————————————————————————————— Regions ————————————————————————————————— //

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
};

#[derive(Debug)]
pub struct Region {
    start: usize,
    end: usize,
    read_count: usize,
    write_count: usize,
    exec_count: usize,
    super_count: usize,
    ref_count: usize,
    next: Option<Handle<Region>>,
}

impl Region {
    fn new(start: usize, end: usize, ops: MemOps) -> Self {
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

    pub fn same_counts(&self, other: &Self) -> bool {
        self.ref_count == other.ref_count
            && self.read_count == other.read_count
            && self.write_count == other.write_count
            && self.exec_count == other.exec_count
            && self.super_count == other.super_count
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

impl Cleanable for Region {
    fn clean(&mut self) {
        *self = EMPTY_REGION;
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
            update.update(self.decrease_ops(next, ops, tracker));
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
            self.insert_head(start, end, ops, tracker)?;
            return Ok(PermissionChange::Some);
        };

        let mut change = PermissionChange::None;
        let (mut previous, mut cursor) =
            if let (Some(lower_bound), _) = self.find_lower_bound(start, tracker) {
                let region = &tracker[lower_bound];
                if start == region.start {
                    // Regions have the same start
                    let (previous, update) =
                        self.partial_add_region_overlapping(start, end, lower_bound, ops, tracker)?;
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
                let previous = self.insert_head(start, cursor, ops, tracker)?;
                change = PermissionChange::Some;
                (previous, cursor)
            };

        // Add the remaining portions of the region
        while cursor < end {
            let (next, update) =
                self.partial_add_region_after(cursor, end, previous, ops, tracker)?;
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
                return self.partial_add_region_overlapping(start, end, next_handle, ops, tracker);
            } else if end > next.start {
                // Fit as much as possible
                end = next.start;
            }
        }
        self.insert_after(start, end, ops, after, tracker)
    }

    fn partial_add_region_overlapping(
        &mut self,
        start: usize,
        end: usize,
        overlapping: Handle<Region>,
        ops: MemOps,
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
        change.update(self.increase_ops(overlapping, ops, tracker));
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
            .allocate(Region::new(start, end, ops).set_next(region.next))
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
        tracker: &mut TrackerPool,
    ) -> Result<Handle<Region>, CapaError> {
        if let Some(head) = self.head {
            assert!(
                tracker[head].start >= end,
                "Region should be sorted by address"
            );
        }

        let region = Region::new(start, end, ops).set_next(self.head);
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
        tracker: &mut TrackerPool,
    ) -> PermissionChange {
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
        return change;
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
        tracker: &mut TrackerPool,
    ) -> PermissionChange {
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
        return change;
    }

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
            if tracker[prev].end == tracker[current].start
                && (tracker[prev].same_counts(&tracker[current])
                    || tracker[current].start == tracker[current].end
                    || tracker[prev].start == tracker[prev].end)
            {
                // Coalesce
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

    pub fn permissions<'a>(&'a self, pool: &'a TrackerPool) -> PermissionIterator<'a> {
        PermissionIterator {
            tracker: self,
            pool,
            next: self.head,
        }
    }
}

impl Cleanable for RegionTracker {
    fn clean(&mut self) {
        self.head = None;
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

/// An iterator over a domain's memory access permissions.
pub struct PermissionIterator<'a> {
    tracker: &'a RegionTracker,
    pool: &'a TrackerPool,
    next: Option<Handle<Region>>,
}

pub struct MemoryPermission {
    pub start: usize,
    pub end: usize,
    pub ops: MemOps,
}

impl MemoryPermission {
    pub fn size(&self) -> usize {
        self.end - self.start
    }
}

impl<'a> Iterator for PermissionIterator<'a> {
    type Item = MemoryPermission;

    fn next(&mut self) -> Option<Self::Item> {
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
        let (end, ops) = {
            let reg = &self.pool[handle.unwrap()];
            (reg.end, reg.get_ops())
        };

        let mut next = None;
        for (handle, _region) in self.tracker.iter_from(handle, self.pool).skip(1) {
            //TODO(aghosn) charly had some optimization here that I had to remove.
            //We can put something correct here in the future.
            next = Some(handle);
            break;
        }

        self.next = next;
        Some(MemoryPermission { start, end, ops })
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {
    use super::*;

    /// Snapshot testing
    ///
    /// Checks that the given struct matches the provided snapshot.
    fn snap<T: core::fmt::Display>(snap: &str, obj: T) {
        assert_eq!(snap, &format!("{}", obj));
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
            .add_region(0x100, 0x1000, MEMOPS_ALL, &mut pool)
            .unwrap();

        // Should return None if there is no lower bound region
        assert_eq!(tracker.find_lower_bound(0x50, &mut pool), (None, None));

        let head = tracker.head;
        assert_eq!(tracker.find_lower_bound(0x100, &mut pool), (head, None));
        assert_eq!(tracker.find_lower_bound(0x200, &mut pool), (head, None));
    }

    #[test]
    fn region_add() {
        // Region is added as head
        let mut tracker = RegionTracker::new();
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        tracker
            .add_region(0x300, 0x400, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(0x100, 0x200, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        // Region is added as head, but overlap
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(0x200, 0x400, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x200, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(0x100, 0x300, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x300 | 2 (2 - 2 - 2 - 2)] -> [0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        // Region is completely included
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(0x100, 0x400, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x100, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(0x200, 0x300, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x300 | 2 (2 - 2 - 2 - 2)] -> [0x300, 0x400 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        // Region is bridging two existing one
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(0x100, 0x400, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x100, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(0x500, 0x1000, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap(
            "{[0x100, 0x400 | 1 (1 - 1 - 1 - 1)] -> [0x500, 0x1000 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );
        tracker
            .add_region(0x200, 0x600, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x400 | 2 (2 - 2 - 2 - 2)] -> [0x400, 0x500 | 1 (1 - 1 - 1 - 1)] -> [0x500, 0x600 | 2 (2 - 2 - 2 - 2)] -> [0x600, 0x1000 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));

        // Region is overlapping two adjacent regions
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(0x200, 0x300, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x200, 0x300 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(0x300, 0x400, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x200, 0x400 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(0x100, 0x500, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x400 | 2 (2 - 2 - 2 - 2)] -> [0x400, 0x500 | 1 (1 - 1 - 1 - 1)]}",
            &tracker.iter(&pool),
        );

        // Region is added twice
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(0x100, 0x200, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(0x100, 0x200, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x100, 0x200 | 2 (2 - 2 - 2 - 2)]}", &tracker.iter(&pool));

        // Regions have the same end
        let mut tracker = RegionTracker::new();
        tracker
            .add_region(0x200, 0x300, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap("{[0x200, 0x300 | 1 (1 - 1 - 1 - 1)]}", &tracker.iter(&pool));
        tracker
            .add_region(0x100, 0x300, MEMOPS_ALL, &mut pool)
            .unwrap();
        snap(
            "{[0x100, 0x200 | 1 (1 - 1 - 1 - 1)] -> [0x200, 0x300 | 2 (2 - 2 - 2 - 2)]}",
            &tracker.iter(&pool),
        );
    }

    #[test]
    fn refcount() {
        let mut tracler = RegionTracker::new();
        let mut pool = TrackerPool::new([EMPTY_REGION; NB_TRACKER]);
        tracler
            .add_region(0x100, 0x300, MEMOPS_ALL, &mut pool)
            .unwrap();
        tracler
            .add_region(0x600, 0x1000, MEMOPS_ALL, &mut pool)
            .unwrap();
        tracler
            .add_region(0x200, 0x400, MEMOPS_ALL, &mut pool)
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
