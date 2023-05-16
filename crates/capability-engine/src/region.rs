use core::fmt;

use crate::config::NB_REGIONS_PER_DOMAIN;
use crate::gen_arena::{GenArena, Handle};
use crate::CapaError;

#[derive(Clone, Copy, Debug)]
pub struct AccessRights {
    pub start: usize,
    pub end: usize,
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

pub struct Region {
    start: usize,
    end: usize,
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
}

// ————————————————————————————— RegionTracker —————————————————————————————— //

pub struct RegionTracker {
    regions: GenArena<Region, NB_REGIONS_PER_DOMAIN>,
    head: Option<Handle<Region>>,
}

impl RegionTracker {
    pub const fn new() -> Self {
        const EMPTY_REGIION: Region = Region {
            start: 0,
            end: 0,
            ref_count: 0,
            next: None,
        };

        Self {
            regions: GenArena::new([EMPTY_REGIION; NB_REGIONS_PER_DOMAIN]),
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
    ) -> Result<PermissionChange, CapaError> {
        log::trace!("Removing region [0x{:x}, 0x{:x}]", start, end);

        let Some(lower_bound_handle) = self.find_lower_bound(start) else {
            log::trace!("Region does not exist");
            return Err(CapaError::InvalidRegion);
        };

        assert_eq!(
            self.regions[lower_bound_handle].start, start,
            "Remove region must specify exact boundaries"
        );

        let mut change = PermissionChange::None;
        let mut next = lower_bound_handle;
        while self.regions[next].start < end {
            let update = self.decrease_refcount(next);
            change.update(update);
            // TODO: Coalesce & free regions

            match &self.regions[next].next {
                Some(handle) => {
                    next = *handle;
                }
                None => {
                    break;
                }
            }
        }

        Ok(change)
    }

    pub fn add_region(&mut self, start: usize, end: usize) -> Result<PermissionChange, CapaError> {
        log::trace!("Adding region [0x{:x}, 0x{:x}]", start, end);

        // There is no region yet, insert head and exit
        let Some(head) = self.head else {
            self.insert_head(start, end)?;
            return Ok(PermissionChange::Some);
        };

        let mut change = PermissionChange::None;
        let (mut previous, mut cursor) = if let Some(lower_bound) = self.find_lower_bound(start) {
            let region = &self.regions[lower_bound];
            if start == region.start {
                // Regions have the same start
                let (previous, update) =
                    self.partial_add_region_overlapping(start, end, lower_bound)?;
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
            let previous = self.insert_head(start, cursor)?;
            change = PermissionChange::Some;
            (previous, cursor)
        };

        // Add the remaining portions of the region
        while cursor < end {
            let (next, update) = self.partial_add_region_after(cursor, end, previous)?;
            previous = next;
            change.update(update);
            cursor = self.regions[previous].end;
        }
        Ok(change)
    }

    fn partial_add_region_after(
        &mut self,
        start: usize,
        end: usize,
        after: Handle<Region>,
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
                return self.partial_add_region_overlapping(start, end, next_handle);
            } else if end > next.start {
                // Fit as much as possible
                end = next.start;
            }
        }

        self.insert_after(start, end, after)
    }

    fn partial_add_region_overlapping(
        &mut self,
        start: usize,
        end: usize,
        overlapping: Handle<Region>,
    ) -> Result<(Handle<Region>, PermissionChange), CapaError> {
        let region = &self.regions[overlapping];
        assert!(
            region.start == start,
            "Region is not overlapping from the start"
        );

        if end < region.end {
            self.split_region_at(overlapping, end)?;
        }
        let change = self.increase_refcount(overlapping);
        Ok((overlapping, change))
    }

    /// Returns a handle to the region with the closest (inferior or equal) start address.
    fn find_lower_bound(&self, start: usize) -> Option<Handle<Region>> {
        let mut closest = self.head?;

        if self.regions[closest].start > start {
            // The first region already starts at a higher address
            return None;
        }

        for (handle, region) in self {
            if region.start <= start {
                closest = handle
            } else {
                break;
            }
        }

        Some(closest)
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
            ref_count: region.ref_count,
            next: region.next,
        };
        let second_half_handle = self
            .regions
            .allocate(second_half)
            .ok_or(CapaError::OutOfMemory)?;

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
            .ok_or(CapaError::OutOfMemory)?;
        let region = &mut self.regions[after];
        region.next = Some(handle);

        // There is alway a permission change in this case
        Ok((handle, PermissionChange::Some))
    }

    fn insert_head(&mut self, start: usize, end: usize) -> Result<Handle<Region>, CapaError> {
        if let Some(head) = self.head {
            assert!(
                self.regions[head].start >= end,
                "Region should be sorted by address"
            );
        }

        let region = Region::new(start, end).set_next(self.head);
        let handle = self
            .regions
            .allocate(region)
            .ok_or(CapaError::OutOfMemory)?;
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

    fn decrease_refcount(&mut self, handle: Handle<Region>) -> PermissionChange {
        let region = &mut self.regions[handle];
        region.ref_count = region.ref_count.checked_sub(1).unwrap();

        if region.ref_count == 0 {
            PermissionChange::Some
        } else {
            PermissionChange::None
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
        assert_eq!(regions.find_lower_bound(0x50), None);

        let head = regions.head;
        assert_eq!(regions.find_lower_bound(0x100), head);
        assert_eq!(regions.find_lower_bound(0x200), head);
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
        snap("{[0x200, 0x300 | 1] -> [0x300, 0x400 | 1]}", &pool);
        pool.add_region(0x100, 0x500).unwrap();
        snap("{[0x100, 0x200 | 1] -> [0x200, 0x300 | 2] -> [0x300, 0x400 | 2] -> [0x400, 0x500 | 1]}", &pool);

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
                "[0x{:x}, 0x{:x} | {}]",
                region.start, region.end, region.ref_count
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
