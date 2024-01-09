//! Region Capabilities

use crate::config::NB_REGIONS;
use crate::domain::{activate_region, insert_capa, DomainPool};
use crate::region::TrackerPool;
use crate::region_capa::RegionPool;
use crate::update::UpdateBuffer;
use crate::{AccessRights, CapaError, Domain, GenArena, Handle, LocalCapa};

pub(crate) type NewRegionPool = GenArena<NewRegionCapa, NB_REGIONS>;
pub const EMPTY_NEW_REGION_CAPA: NewRegionCapa = NewRegionCapa::new_invalid();

pub enum RegionKind {
    Root,
    Alias,
    Carve,
}

pub struct NewRegionCapa {
    domain: Handle<Domain>,
    child_list_head: Option<Handle<NewRegionCapa>>,
    next_sibling: Option<Handle<NewRegionCapa>>,
    kind: RegionKind,
    pub(crate) is_confidential: bool,
    pub(crate) access: AccessRights,
}

impl NewRegionCapa {
    pub const fn new_invalid() -> Self {
        Self {
            domain: Handle::new_invalid(),
            kind: RegionKind::Root,
            child_list_head: None,
            next_sibling: None,
            is_confidential: false,
            access: AccessRights::none(),
        }
    }

    pub fn new(domain: Handle<Domain>, kind: RegionKind, access: AccessRights) -> Self {
        Self {
            domain,
            kind,
            child_list_head: None,
            next_sibling: None,
            is_confidential: false,
            access,
        }
    }

    pub fn is_carved(&self) -> bool {
        match self.kind {
            RegionKind::Carve => true,
            _ => false,
        }
    }

    /// Update the confidential attripute.
    pub fn confidential(mut self, confidential: bool) -> Self {
        self.is_confidential = confidential;
        self
    }

    /// Returns true if the region starts before the other
    pub fn is_smaller(&self, access: &AccessRights) -> bool {
        self.access.start <= access.start
    }
}

pub fn alias(
    handle: Handle<NewRegionCapa>,
    regions: &mut NewRegionPool,
    old_regions: &mut RegionPool,
    domains: &mut DomainPool,
    tracker: &mut TrackerPool,
    updates: &mut UpdateBuffer,
    access: AccessRights,
) -> Result<LocalCapa, CapaError> {
    let region = &regions[handle];
    let domain = region.domain;

    // Check capacity
    // TODO

    let new_handle = alias_region(handle, regions, access)?;
    let local_capa = insert_capa(domain, new_handle, old_regions, domains)?;
    activate_region(domain, access, domains, updates, tracker)?;

    Ok(local_capa)
}

/// Create a new child region and append it to the parent.
fn alias_region(
    handle: Handle<NewRegionCapa>,
    regions: &mut NewRegionPool,
    access: AccessRights,
) -> Result<Handle<NewRegionCapa>, CapaError> {
    let region = regions.get(handle).ok_or(CapaError::InvalidCapa)?;
    let domain_handle = region.domain;

    if !access.new_is_valid() || !check_alias(handle, &access, regions) {
        return Err(CapaError::InvalidOperation);
    }

    let new_region =
        NewRegionCapa::new(domain_handle, RegionKind::Alias, access).confidential(false);
    let new_handle = regions.allocate(new_region).ok_or(CapaError::OutOfMemory)?;
    insert_child(handle, new_handle, regions);
    Ok(new_handle)
}

pub fn carve(
    handle: Handle<NewRegionCapa>,
    regions: &mut NewRegionPool,
    old_regions: &mut RegionPool,
    domains: &mut DomainPool,
    access: AccessRights,
) -> Result<LocalCapa, CapaError> {
    let region = &regions[handle];
    let domain = region.domain;

    // Check capacity
    // TODO

    let new_handle = carve_region(handle, regions, access)?;
    let local_capa = insert_capa(domain, new_handle, old_regions, domains)?;
    // No need to update tracker here, the domain lost access to the new region one time ang
    // gained it back at the same time.

    Ok(local_capa)
}

/// Create a new child region and append it to the parent.
fn carve_region(
    handle: Handle<NewRegionCapa>,
    regions: &mut NewRegionPool,
    access: AccessRights,
) -> Result<Handle<NewRegionCapa>, CapaError> {
    let region = regions.get(handle).ok_or(CapaError::InvalidCapa)?;
    let domain_handle = region.domain;
    let is_confidential = region.is_confidential;

    if !access.new_is_valid() || !check_carve(handle, &access, regions) {
        return Err(CapaError::InvalidOperation);
    }

    let new_region =
        NewRegionCapa::new(domain_handle, RegionKind::Carve, access).confidential(is_confidential);
    let new_handle = regions.allocate(new_region).ok_or(CapaError::OutOfMemory)?;
    insert_child(handle, new_handle, regions);
    Ok(new_handle)
}

/// Insert a child capability in the sorted linked list, while maintaining the ordering.
fn insert_child(
    parent: Handle<NewRegionCapa>,
    child: Handle<NewRegionCapa>,
    regions: &mut NewRegionPool,
) {
    let access = regions[child].access;
    assert!(regions[child].next_sibling.is_none());

    // Check the head first
    let next = match regions[parent].child_list_head {
        Some(head) => head,
        None => {
            // Let's add the new region as the head of the list and we are done
            regions[parent].child_list_head = Some(child);
            return;
        }
    };

    // We need to do the first iteration outside the loop, because we might need to update the head
    let next_region = &regions[next];
    if !next_region.is_smaller(&access) {
        // Update the head
        regions[parent].child_list_head = Some(child);
        regions[child].next_sibling = Some(next);
        return;
    }
    let mut previous = next;
    let mut next = regions[previous].next_sibling;

    // Iterate over the regions
    loop {
        let next_handle = match next {
            Some(h) => h,
            None => {
                // No more regions, we insert after the last one.
                regions[previous].next_sibling = Some(child);
                return;
            }
        };

        // Check if we should insert here
        let next_region = &regions[next_handle];
        if !next_region.is_smaller(&access) {
            regions[previous].next_sibling = Some(child);
            regions[child].next_sibling = Some(next_handle);
            return;
        }

        // Go to next region
        previous = next_handle;
        next = next_region.next_sibling;
    }
}

/// Panics if the child list is malformed.
fn validate_child_list(region: Handle<NewRegionCapa>, regions: &NewRegionPool) {
    let parent_access = regions[region].access;
    let mut cursor = regions[region].child_list_head;
    let mut prev_access: Option<AccessRights> = None;

    // TODO: check for overlap with carved regions.
    while let Some(h) = cursor {
        let current = &regions[h];

        if let Some(prev_access) = prev_access {
            if prev_access.start > current.access.start {
                panic!("Child list is not properly sorted");
            }
        }
        if parent_access.start > current.access.start || parent_access.end < current.access.end {
            panic!("Child is not contain within parent region");
        }

        cursor = current.next_sibling;
        prev_access = Some(current.access.clone());
    }
}

/// Checks that a region with the provided access rights can be carved from the parent.
fn check_alias(
    parent: Handle<NewRegionCapa>,
    access: &AccessRights,
    regions: &NewRegionPool,
) -> bool {
    let region = &regions[parent];
    if region.access.start > access.start || region.access.end < access.end {
        return false;
    }

    for child in RegionIterator::child_list(parent, regions) {
        if child.is_carved() && access.overlap(&child.access) {
            return false;
        }
    }

    true
}

/// Checks that a region with the provided access rights can be carved from the parent.
fn check_carve(
    parent: Handle<NewRegionCapa>,
    access: &AccessRights,
    regions: &NewRegionPool,
) -> bool {
    let region = &regions[parent];
    if region.access.start > access.start || region.access.end < access.end {
        return false;
    }

    for child in RegionIterator::child_list(parent, regions) {
        if access.overlap(&child.access) {
            return false;
        }
    }

    true
}

struct RegionIterator<'a> {
    next: Option<Handle<NewRegionCapa>>,
    regions: &'a NewRegionPool,
}

impl<'a> RegionIterator<'a> {
    fn child_list(parent: Handle<NewRegionCapa>, regions: &'a NewRegionPool) -> Self {
        RegionIterator {
            next: regions[parent].child_list_head,
            regions,
        }
    }
}

impl<'a> Iterator for RegionIterator<'a> {
    type Item = &'a NewRegionCapa;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next?;
        let region = &self.regions[next];
        self.next = region.next_sibling;
        Some(region)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MEMOPS_ALL;

    fn dummy_region(start: usize, end: usize) -> NewRegionCapa {
        NewRegionCapa::new(
            Handle::new_invalid(),
            RegionKind::Root,
            AccessRights {
                start,
                end,
                ops: MEMOPS_ALL,
            },
        )
    }

    fn dummy_access(start: usize, end: usize) -> AccessRights {
        AccessRights {
            start,
            end,
            ops: MEMOPS_ALL,
        }
    }

    #[test]
    fn alias() {
        let mut pool = GenArena::new([EMPTY_NEW_REGION_CAPA; NB_REGIONS]);
        let root = pool.allocate(dummy_region(0x10, 0x100)).unwrap();
        validate_child_list(root, &pool);

        // Should work
        alias_region(root, &mut pool, dummy_access(0x20, 0x30)).unwrap();
        validate_child_list(root, &pool);
        alias_region(root, &mut pool, dummy_access(0x20, 0x30)).unwrap();
        validate_child_list(root, &pool);
        alias_region(root, &mut pool, dummy_access(0x25, 0x30)).unwrap();
        validate_child_list(root, &pool);
        alias_region(root, &mut pool, dummy_access(0x10, 0x40)).unwrap();
        validate_child_list(root, &pool);
        alias_region(root, &mut pool, dummy_access(0x50, 0x70)).unwrap();
        validate_child_list(root, &pool);

        // Should NOT work
        assert!(alias_region(root, &mut pool, dummy_access(0x5, 0x30)).is_err());
        assert!(alias_region(root, &mut pool, dummy_access(0x20, 0x120)).is_err());
        assert!(alias_region(root, &mut pool, dummy_access(0x30, 0x20)).is_err());
    }

    #[test]
    fn carve() {
        let mut pool = GenArena::new([EMPTY_NEW_REGION_CAPA; NB_REGIONS]);
        let root = pool.allocate(dummy_region(0x10, 0x100)).unwrap();
        validate_child_list(root, &pool);

        // Should work
        carve_region(root, &mut pool, dummy_access(0x20, 0x30)).unwrap();
        validate_child_list(root, &pool);
        carve_region(root, &mut pool, dummy_access(0x50, 0x60)).unwrap();
        validate_child_list(root, &pool);
        carve_region(root, &mut pool, dummy_access(0x60, 0x70)).unwrap();
        validate_child_list(root, &pool);

        // Should NOT work
        assert!(carve_region(root, &mut pool, dummy_access(0x5, 0x30)).is_err());
        assert!(carve_region(root, &mut pool, dummy_access(0x20, 0x30)).is_err());
        assert!(carve_region(root, &mut pool, dummy_access(0x22, 0x28)).is_err());
        assert!(carve_region(root, &mut pool, dummy_access(0x30, 0x20)).is_err());
        assert!(alias_region(root, &mut pool, dummy_access(0x20, 0x25)).is_err());
    }
}
