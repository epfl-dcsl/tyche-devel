use core::fmt;

use bitflags::bitflags;

use crate::config::NB_REGIONS_PER_DOMAIN;
use crate::gen_arena::{GenArena, Handle};
use crate::CapaError;

bitflags! {
    pub struct MemOps: u8 {
         const NONE  = 0;
         const READ  = 1 << 0;
         const WRITE = 1 << 1;
         const EXEC  = 1 << 2;
         const SUPER = 1 << 3;
    }
}

pub const MEMOPS_ALL: MemOps = MemOps::READ
    .union(MemOps::WRITE)
    .union(MemOps::EXEC)
    .union(MemOps::SUPER);

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
}

#[derive(Clone, Copy, Debug)]
pub struct AccessRights {
    pub start: usize,
    pub end: usize,
    pub ops: MemOps,
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
    fn new(start: usize, end: usize) -> Self {
        if start >= end {
            log::error!(
                "Region start must be smaller than end, got start = {} and end = {}",
                start,
                end
            );
            panic!("Invalid region");
        }
        Self {
            start,
            end,
            read_count: 0,
            write_count: 0,
            exec_count: 0,
            super_count: 0,
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
}

// ————————————————————————————— RegionTracker —————————————————————————————— //

pub struct RegionTracker {
    regions: GenArena<Region, NB_REGIONS_PER_DOMAIN>,
    head: Option<Handle<Region>>,
}

impl RegionTracker {
    pub const fn new() -> Self {
        const EMPTY_REGION: Region = Region {
            start: 0,
            end: 0,
            read_count: 0,
            write_count: 0,
            exec_count: 0,
            super_count: 0,
            ref_count: 0,
            next: None,
        };

        Self {
            regions: GenArena::new([EMPTY_REGION; NB_REGIONS_PER_DOMAIN]),
            head: None,
        }
    }

    pub fn get_refcount(&self, start: usize, end: usize) -> usize {
        let mut count = 0;

        for (_, region) in self {
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
    ) -> Result<PermissionChange, CapaError> {
        log::trace!("Removing region [0x{:x}, 0x{:x}]", start, end);

        let (Some(mut bound), mut prev) = self.find_lower_bound(start) else {
            log::trace!("Region does not exist");
            return Err(CapaError::InvalidRegion);
        };

        // Check if we need a split for the start.
        if self.regions[bound].start < start {
            prev = Some(bound);
            bound = self.split_region_at(bound, start)?;
        }
        // Check if we need a split for the end.
        if self.regions[bound].end > end {
            let _ = self.split_region_at(bound, end)?;
        }

        assert_eq!(
            self.regions[bound].start, start,
            "Remove region must specify exact boundaries"
        );

        let mut change = PermissionChange::None;
        let mut next = bound;
        while self.regions[next].start < end {
            let mut update = self.decrease_refcount(next);
            update.update(self.decrease_ops(next, ops));
            change.update(update);

            // Free regions with ref_count 0.
            if self.regions[next].ref_count == 0 {
                // Remove the element from the list.
                let to_visit = self.regions[next].next;
                match prev {
                    Some(handle) => {
                        self.regions[handle].next = self.regions[next].next;
                    }
                    None => {
                        self.head = self.regions[next].next;
                    }
                }
                // Free the region.
                self.regions.free(next);

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

            match &self.regions[next].next {
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
        self.coalesce();
        Ok(change)
    }

    pub fn add_region(
        &mut self,
        start: usize,
        end: usize,
        ops: MemOps,
    ) -> Result<PermissionChange, CapaError> {
        log::trace!("Adding region [0x{:x}, 0x{:x}]", start, end);

        // There is no region yet, insert head and exit
        let Some(head) = self.head else {
            self.insert_head(start, end, ops)?;
            return Ok(PermissionChange::Some);
        };

        let mut change = PermissionChange::None;
        let (mut previous, mut cursor) =
            if let (Some(lower_bound), _) = self.find_lower_bound(start) {
                let region = &self.regions[lower_bound];
                if start == region.start {
                    // Regions have the same start
                    let (previous, update) =
                        self.partial_add_region_overlapping(start, end, lower_bound, ops)?;
                    change.update(update);
                    let cursor = self.regions[previous].end;
                    (previous, cursor)
                } else if region.contains(start) {
                    // Region start in the middle of the lower bound region
                    self.split_region_at(lower_bound, start)?;
                    (lower_bound, start)
                } else {
                    // Region starts after lower bound region
                    (lower_bound, start)
                }
            } else {
                let head = &self.regions[head];
                let cursor = core::cmp::min(end, head.start);
                let previous = self.insert_head(start, cursor, ops)?;
                change = PermissionChange::Some;
                (previous, cursor)
            };

        // Add the remaining portions of the region
        while cursor < end {
            let (next, update) = self.partial_add_region_after(cursor, end, previous, ops)?;
            previous = next;
            change.update(update);
            cursor = self.regions[previous].end;
        }

        // Coalesce.
        self.coalesce();
        Ok(change)
    }

    fn partial_add_region_after(
        &mut self,
        start: usize,
        end: usize,
        after: Handle<Region>,
        ops: MemOps,
    ) -> Result<(Handle<Region>, PermissionChange), CapaError> {
        let region = &mut self.regions[after];

        assert!(start < end, "Tried to add invalid region");
        assert!(region.end <= start, "Invalid add_region_after");

        // Check how much of the region can fit before the next one
        let mut end = end;
        if let Some(next_handle) = region.next {
            let next = &mut self.regions[next_handle];
            if start == next.start {
                // Overlapping
                return self.partial_add_region_overlapping(start, end, next_handle, ops);
            } else if end > next.start {
                // Fit as much as possible
                end = next.start;
            }
        }
        self.insert_after(start, end, ops, after)
    }

    fn partial_add_region_overlapping(
        &mut self,
        start: usize,
        end: usize,
        overlapping: Handle<Region>,
        ops: MemOps,
    ) -> Result<(Handle<Region>, PermissionChange), CapaError> {
        let region = &self.regions[overlapping];
        assert!(
            region.start == start,
            "Region is not overlapping from the start"
        );

        if end < region.end {
            self.split_region_at(overlapping, end)?;
        }
        let mut change = self.increase_refcount(overlapping);
        change.update(self.increase_ops(overlapping, ops));
        Ok((overlapping, change))
    }

    /// Returns a handle to the region with the closest (inferior or equal) start address.
    /// First value is the closest, second is the previous element.
    fn find_lower_bound(&self, start: usize) -> (Option<Handle<Region>>, Option<Handle<Region>>) {
        let Some(mut closest) = self.head else {return (None, None)} ;

        if self.regions[closest].start > start {
            // The first region already starts at a higher address
            return (None, None);
        }
        let mut prev = None;
        let mut iter = None;
        for (handle, region) in self {
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
    ) -> Result<Handle<Region>, CapaError> {
        let region = &self.regions[handle];
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
        let second_half_handle = self.regions.allocate(second_half).ok_or_else(|| {
            log::trace!("Unable to allocate new region!");
            //TODO(aghosn) this one fails.
            CapaError::OutOfMemory
        })?;

        // Update the first half
        let region = &mut self.regions[handle];
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
    ) -> Result<(Handle<Region>, PermissionChange), CapaError> {
        let region = &self.regions[after];
        assert!(start >= region.end, "Regions should be sorted by addresses");
        if let Some(next) = region.next {
            assert!(
                end <= self.regions[next].start,
                "Regions should be sorted by addresses"
            );
        }

        let handle = self
            .regions
            .allocate(Region::new(start, end).set_next(region.next))
            .ok_or_else(|| {
                log::trace!("Unable to allocate new region!");
                CapaError::OutOfMemory
            })?;
        self.increase_ops(handle, ops);
        let region = &mut self.regions[after];
        region.next = Some(handle);

        // There is alway a permission change in this case
        Ok((handle, PermissionChange::Some))
    }

    fn insert_head(
        &mut self,
        start: usize,
        end: usize,
        ops: MemOps,
    ) -> Result<Handle<Region>, CapaError> {
        if let Some(head) = self.head {
            assert!(
                self.regions[head].start >= end,
                "Region should be sorted by address"
            );
        }

        let region = Region::new(start, end).set_next(self.head);
        let handle = self.regions.allocate(region).ok_or_else(|| {
            log::trace!("Unable to allocate new region!");
            CapaError::OutOfMemory
        })?;
        self.increase_ops(handle, ops);
        self.head = Some(handle);
        Ok(handle)
    }

    fn increase_refcount(&mut self, handle: Handle<Region>) -> PermissionChange {
        let region = &mut self.regions[handle];
        region.ref_count += 1;

        if region.ref_count == 1 {
            PermissionChange::Some
        } else {
            PermissionChange::None
        }
    }

    fn increase_ops(&mut self, handle: Handle<Region>, ops: MemOps) -> PermissionChange {
        let region = &mut self.regions[handle];
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

    fn decrease_refcount(&mut self, handle: Handle<Region>) -> PermissionChange {
        let region = &mut self.regions[handle];
        region.ref_count = region.ref_count.checked_sub(1).unwrap();

        if region.ref_count == 0 {
            PermissionChange::Some
        } else {
            PermissionChange::None
        }
    }

    fn decrease_ops(&mut self, handle: Handle<Region>, ops: MemOps) -> PermissionChange {
        let region = &mut self.regions[handle];
        let mut change = PermissionChange::None;
        if ops.contains(MemOps::READ) {
            region.read_count.checked_sub(1).unwrap();
            if region.read_count == 0 {
                change = PermissionChange::Some;
            }
        }
        if ops.contains(MemOps::WRITE) {
            region.write_count.checked_sub(1).unwrap();
            if region.write_count == 0 {
                change = PermissionChange::Some;
            }
        }
        if ops.contains(MemOps::EXEC) {
            region.exec_count.checked_sub(1).unwrap();
            if region.exec_count == 0 {
                change = PermissionChange::Some;
            }
        }
        if ops.contains(MemOps::SUPER) {
            region.super_count.checked_sub(1).unwrap();
            if region.super_count == 0 {
                change = PermissionChange::Some;
            }
        }
        return change;
    }

    fn coalesce(&mut self) {
        if self.head == None {
            // Nothing to do.
            return;
        }
        let mut prev = self.head.unwrap();
        let mut curr = self.regions[prev].next;

        // Go through the list.
        while curr != None {
            let current = curr.unwrap();
            if self.regions[prev].end == self.regions[current].start
                && (self.regions[prev].same_counts(&self.regions[current])
                    || self.regions[current].start == self.regions[current].end
                    || self.regions[prev].start == self.regions[prev].end)
            {
                // Coalesce
                if self.regions[prev].start == self.regions[prev].end {
                    self.regions[prev].ref_count = self.regions[current].ref_count;
                }
                self.regions[prev].next = self.regions[current].next;
                self.regions[prev].end = self.regions[current].end;
                self.regions.free(curr.unwrap());
                curr = self.regions[prev].next;
                continue;
            }
            prev = curr.unwrap();
            curr = self.regions[current].next;
        }
    }

    pub fn iter(&self) -> RegionIterator {
        RegionIterator {
            tracker: self,
            next: self.head,
        }
    }

    pub fn iter_from(&self, start: Option<Handle<Region>>) -> RegionIterator {
        RegionIterator {
            tracker: self,
            next: start,
        }
    }

    pub fn permissions(&self) -> PermissionIterator {
        PermissionIterator {
            tracker: self,
            next: self.head,
        }
    }
}

// ———————————————————————————— Region Iterators ———————————————————————————— //

pub struct RegionIterator<'a> {
    tracker: &'a RegionTracker,
    next: Option<Handle<Region>>,
}

impl<'a> Iterator for RegionIterator<'a> {
    type Item = (Handle<Region>, &'a Region);

    fn next(&mut self) -> Option<Self::Item> {
        let handle = self.next?;
        let region = &self.tracker.regions[handle];

        self.next = region.next;
        Some((handle, region))
    }
}

impl<'a> IntoIterator for &'a RegionTracker {
    type Item = (Handle<Region>, &'a Region);
    type IntoIter = RegionIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over a domain's memory access permissions.
pub struct PermissionIterator<'a> {
    tracker: &'a RegionTracker,
    next: Option<Handle<Region>>,
}

pub struct MemoryPermission {
    pub start: usize,
    pub end: usize,
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
        for (h, region) in self.tracker.iter_from(self.next) {
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
        let mut end = self.tracker.regions[handle.unwrap()].end;

        let mut next = None;
        for (handle, region) in self.tracker.iter_from(handle).skip(1) {
            if region.ref_count > 0 && region.start == end {
                // Merge regions
                end = region.end;
            } else {
                next = Some(handle);
                break;
            }
        }

        self.next = next;
        Some(MemoryPermission { start, end })
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
        let mut regions = RegionTracker::new();
        regions.add_region(0x100, 0x1000).unwrap();

        // Should return None if there is no lower bound region
        assert_eq!(regions.find_lower_bound(0x50), (None, None));

        let head = regions.head;
        assert_eq!(regions.find_lower_bound(0x100), (head, None));
        assert_eq!(regions.find_lower_bound(0x200), (head, None));
    }

    #[test]
    fn region_add() {
        // Region is added as head
        let mut pool = RegionTracker::new();
        pool.add_region(0x300, 0x400).unwrap();
        snap("{[0x300, 0x400 | 1]}", &pool);
        pool.add_region(0x100, 0x200).unwrap();
        snap("{[0x100, 0x200 | 1] -> [0x300, 0x400 | 1]}", &pool);

        // Region is added as head, but overlap
        let mut pool = RegionTracker::new();
        pool.add_region(0x200, 0x400).unwrap();
        snap("{[0x200, 0x400 | 1]}", &pool);
        pool.add_region(0x100, 0x300).unwrap();
        snap(
            "{[0x100, 0x200 | 1] -> [0x200, 0x300 | 2] -> [0x300, 0x400 | 1]}",
            &pool,
        );

        // Region is completely included
        let mut pool = RegionTracker::new();
        pool.add_region(0x100, 0x400).unwrap();
        snap("{[0x100, 0x400 | 1]}", &pool);
        pool.add_region(0x200, 0x300).unwrap();
        snap(
            "{[0x100, 0x200 | 1] -> [0x200, 0x300 | 2] -> [0x300, 0x400 | 1]}",
            &pool,
        );

        // Region is bridging two existing one
        let mut pool = RegionTracker::new();
        pool.add_region(0x100, 0x400).unwrap();
        snap("{[0x100, 0x400 | 1]}", &pool);
        pool.add_region(0x500, 0x1000).unwrap();
        snap("{[0x100, 0x400 | 1] -> [0x500, 0x1000 | 1]}", &pool);
        pool.add_region(0x200, 0x600).unwrap();
        snap("{[0x100, 0x200 | 1] -> [0x200, 0x400 | 2] -> [0x400, 0x500 | 1] -> [0x500, 0x600 | 2] -> [0x600, 0x1000 | 1]}", &pool);

        // Region is overlapping two adjacent regions
        let mut pool = RegionTracker::new();
        pool.add_region(0x200, 0x300).unwrap();
        snap("{[0x200, 0x300 | 1]}", &pool);
        pool.add_region(0x300, 0x400).unwrap();
        snap("{[0x200, 0x400 | 1]}", &pool);
        pool.add_region(0x100, 0x500).unwrap();
        snap(
            "{[0x100, 0x200 | 1] -> [0x200, 0x400 | 2] -> [0x400, 0x500 | 1]}",
            &pool,
        );

        // Region is added twice
        let mut pool = RegionTracker::new();
        pool.add_region(0x100, 0x200).unwrap();
        snap("{[0x100, 0x200 | 1]}", &pool);
        pool.add_region(0x100, 0x200).unwrap();
        snap("{[0x100, 0x200 | 2]}", &pool);

        // Regions have the same end
        let mut pool = RegionTracker::new();
        pool.add_region(0x200, 0x300).unwrap();
        snap("{[0x200, 0x300 | 1]}", &pool);
        pool.add_region(0x100, 0x300).unwrap();
        snap("{[0x100, 0x200 | 1] -> [0x200, 0x300 | 2]}", &pool);
    }

    #[test]
    fn refcount() {
        let mut pool = RegionTracker::new();
        pool.add_region(0x100, 0x300).unwrap();
        pool.add_region(0x600, 0x1000).unwrap();
        pool.add_region(0x200, 0x400).unwrap();
        snap("{[0x100, 0x200 | 1] -> [0x200, 0x300 | 2] -> [0x300, 0x400 | 1] -> [0x600, 0x1000 | 1]}", &pool);

        assert_eq!(pool.get_refcount(0x0, 0x50), 0);
        assert_eq!(pool.get_refcount(0x0, 0x100), 0);
        assert_eq!(pool.get_refcount(0x0, 0x150), 1);
        assert_eq!(pool.get_refcount(0x100, 0x200), 1);
        assert_eq!(pool.get_refcount(0x100, 0x250), 2);
        assert_eq!(pool.get_refcount(0x0, 0x250), 2);
        assert_eq!(pool.get_refcount(0x100, 0x400), 2);
        assert_eq!(pool.get_refcount(0x100, 0x500), 2);
        assert_eq!(pool.get_refcount(0x400, 0x500), 0);
        assert_eq!(pool.get_refcount(0x450, 0x500), 0);
        assert_eq!(pool.get_refcount(0x400, 0x2000), 1);
        assert_eq!(pool.get_refcount(0x1500, 0x2000), 0);
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl fmt::Display for AccessRights {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[0x{:x}, 0x{:x}]", self.start, self.end)
    }
}

impl fmt::Display for RegionTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{")?;
        for (_, region) in self {
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
        write!(f, "[0x{:x}, 0x{:x} | RWX]", self.start, self.end)
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
