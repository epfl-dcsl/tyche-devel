use mmu::ioptmapper::PAGE_SIZE;
use mmu::memory_coloring::MemoryColoring;
use utils::GuestPhysAddr;

use super::Segment;
use crate::remapper::EMPTY_SEGMENT;
use crate::{GenArena, MemoryPermission, PermissionIterator, ResourceKind};

/// Unified representation of remappings
/*#[derive(Debug, Clone, Copy, Default)]
pub struct RemapDirective {
    pub hpa: usize,
    pub gpa: usize,
    pub size: usize,
    pub repeat: usize,
}*/

#[derive(Clone)]
pub struct MergedRemapIter<'a, const N: usize, T: MemoryColoring + Clone + Default> {
    simple: [Segment; N],
    simple_len: usize,
    simple_idx: usize,
    simple_next: Option<Segment>,
    compactified_iters: [CompatifiedMappingIter<'a, T>; N],
    compactified_next: [Option<Segment>; N],
    compactified_len: usize,
}

impl<'a, const N: usize, T: MemoryColoring + Clone + Default> MergedRemapIter<'a, N, T> {
    pub fn new(
        simple_arena: &GenArena<Segment, N>,
        mut compact_remaps: [CompatifiedMappingIter<'a, T>; N],
        compactified_remaps_len: usize,
    ) -> Self {
        let mut simple = [EMPTY_SEGMENT; N];
        let mut simple_len = 0;
        for v in simple_arena {
            let v = simple_arena.get(v).unwrap();
            simple[simple_len] = Segment {
                hpa: v.hpa,
                gpa: v.gpa,
                size: v.size,
                repeat: v.repeat,
                next: None,
            };
            simple_len += 1;
        }
        let simple_next = if simple_len == 0 {
            None
        } else {
            Some(simple[0])
        };

        /*let mut compactified_iters = [ColorToPhysIter::default(); N].map(|v| v.clone());
        let mut compactified_len = 0;
        for v in compact_remaps {
            let v = compact_remaps.get(v).unwrap();
            let mut cbm = T::Bitmap::default();
            for x in v.color_range.0..v.color_range.1 {
                cbm.set(x, true);
            }
            let ctp =
                ColorToPhys::new(v.memory_regions, coloring.clone(), cbm, v.additional_filter);
            compactified_iters[compactified_len] = ctp.into_iter();
            compactified_len += 1;
        }*/
        let mut compactified_next = [None; N];
        for idx in 0..compactified_remaps_len {
            let iter = &mut compact_remaps[idx];
            compactified_next[idx] = iter.next();
        }

        Self {
            simple,
            simple_len,
            simple_next,
            simple_idx: 0,
            compactified_iters: compact_remaps,
            compactified_next,
            compactified_len: compactified_remaps_len,
        }
    }
}

impl<'a, const N: usize, T: MemoryColoring + Clone + Default> Iterator
    for MergedRemapIter<'a, N, T>
{
    type Item = Segment;

    /// Fuse all internate iterators an return the remapping instructions sorted by the next HPA (ascending)
    fn next(&mut self) -> Option<Self::Item> {
        //Search for smallest entry in compactified
        let mut next_compactified: Option<(usize, Segment)> = None;
        for idx in 0..self.compactified_len {
            let candidate = match self.compactified_next[idx] {
                Some(v) => v,
                None => continue,
            };

            match next_compactified {
                Some((_, current)) => {
                    if candidate.hpa < current.hpa {
                        next_compactified = Some((idx, candidate));
                    }
                }
                None => next_compactified = Some((idx, candidate)),
            }
        }

        //fuse simple nex with compactified next, returning the one with the smaller hpa
        match (self.simple_next, next_compactified) {
            (None, None) => None,
            //only next_compactified
            (None, Some((idx, v))) => {
                self.compactified_next[idx] = self.compactified_iters[idx].next();
                Some(v)
            }
            //only simple_next
            (Some(v), None) => {
                self.simple_next = if self.simple_idx < self.simple_len {
                    let v = self.simple[self.simple_idx];
                    self.simple_idx += 1;
                    Some(v)
                } else {
                    None
                };
                Some(Segment {
                    hpa: v.hpa,
                    gpa: v.gpa,
                    size: v.size,
                    repeat: v.repeat,
                    next: None,
                })
            }
            (Some(simple), Some((compactified_idx, compactified))) => {
                //TODO: advance to next entry
                if simple.hpa > compactified.hpa {
                    self.simple_next = if self.simple_idx < self.simple_len {
                        let v = self.simple[self.simple_idx];
                        self.simple_idx += 1;
                        Some(v)
                    } else {
                        None
                    };
                    Some(Segment {
                        hpa: simple.hpa,
                        gpa: simple.gpa,
                        size: simple.size,
                        repeat: simple.repeat,
                        next: None,
                    })
                } else {
                    self.compactified_next[compactified_idx] =
                        self.compactified_iters[compactified_idx].next();
                    Some(Segment {
                        hpa: compactified.hpa,
                        gpa: compactified.gpa,
                        size: compactified.size,
                        repeat: compactified.repeat,
                        next: None,
                    })
                }
            }
        }
    }
}

fn next_device<'a, T: MemoryColoring + Clone + Default>(
    iter: &mut PermissionIterator<'a, T>,
) -> Option<MemoryPermission> {
    for x in iter {
        match x.resource_kind {
            ResourceKind::RAM(_) => continue,
            ResourceKind::Device => return Some(x),
        }
    }
    return None;
}

#[derive(Clone)]
pub struct CompatifiedMappingIter<'a, T: MemoryColoring + Clone + Default> {
    permission_iter: PermissionIterator<'a, T>,
    next_blocked_iter: PermissionIterator<'a, T>,
    next_blocked: Option<MemoryPermission>,
    next_ram_gpa: usize,
    highest_device_gpa: Option<GuestPhysAddr>,
    active_ram_range: Option<(MemoryPermission, usize)>,
    //stats
    _mapped_ram_bytes: usize,
    _mapped_device_bytes: usize,
    //total number of contig phys ranges that we used to back the GPA RAM space
    _total_ram_range_count: usize,
    //counts the number of created mappings
    mapping_count: usize,
}

impl<'a, T: MemoryColoring + Clone + Default> Iterator for CompatifiedMappingIter<'a, T> {
    type Item = Segment;

    fn next(&mut self) -> Option<Self::Item> {
        // Case 1: Still have chuncks in memory permission from previous call
        // Case 2: fetch next memory permission from permission iterator
        if self.active_ram_range.is_none() {
            self.active_ram_range = match self.permission_iter.next() {
                Some(r) => Some((r, r.size())),
                None => return None,
            };
        }
        let (range, remaining_chunk_bytes) = match &mut self.active_ram_range {
            Some((range, remaining_bytes)) => (range, remaining_bytes),
            None => panic!("should not happen by construction"),
        };

        if self.mapping_count > 0 && self.mapping_count % 10000 == 0 {
            log::info!("Used {:08} remappings so far", self.mapping_count);
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

                let map_size: usize;
                let mut advance_next_blocked = false;
                match &self.next_blocked {
                    Some(next_blocked) => {
                        //for device mem we need to compare gour gpa with hpa, because we will passtrhough/identity map them
                        assert!(self.next_ram_gpa <= next_blocked.start);
                        let bytes_until_blocked = next_blocked.start - self.next_ram_gpa;
                        assert!(bytes_until_blocked > 0, "bytes untill blocked was 0. next_blocked.hpa = 0x{:x}, next_ram_gpa 0x{:x}", next_blocked.start, self.next_ram_gpa);
                        if *remaining_chunk_bytes < bytes_until_blocked {
                            map_size = *remaining_chunk_bytes;
                        } else {
                            advance_next_blocked = true;
                            map_size = bytes_until_blocked;
                        }
                    }
                    None => {
                        //No more blocked ranges -> can map everything
                        map_size = *remaining_chunk_bytes;
                    }
                }

                assert_eq!(
                    self.next_ram_gpa % PAGE_SIZE,
                    0,
                    "next_ram_gpa is not aligned"
                );
                assert_eq!(map_size % PAGE_SIZE, 0, "map_size ist not aligned");
                assert!(map_size > 0);

                let result = Segment {
                    hpa: range.end - *remaining_chunk_bytes,
                    gpa: self.next_ram_gpa,
                    size: map_size,
                    repeat: 1,
                    next: None,
                };

                self._mapped_ram_bytes += map_size;
                *remaining_chunk_bytes -= map_size;
                self.mapping_count += 1;
                self.next_ram_gpa += map_size;
                if advance_next_blocked {
                    let mut cur_blocked = self
                        .next_blocked
                        .expect("advance_next_blocked true but next block was None");

                    assert_eq!(self.next_ram_gpa, cur_blocked.start,"Requested to advance next blocked, but have not hit it yet. Device GPA 0x{:013x}, next_ram GPA 0x{:013x}",
                    cur_blocked.start, self.next_ram_gpa);
                    self.next_ram_gpa += cur_blocked.size();

                    self.next_blocked = next_device(&mut self.next_blocked_iter);

                    //next blocked might by contiguous -> skip over next until there is a gap
                    while let Some(nb) = self.next_blocked {
                        if nb.start == (cur_blocked.start + cur_blocked.size()) {
                            assert_eq!(
                                    self.next_ram_gpa, nb.start,
                                    "next_ram_gpa 0x{:013x}, nb.start 0x{:013x}, cur_blocked.start 0x{:013x}, cur_blocked.end 0x{:013x}",
                                    self.next_ram_gpa, nb.start, cur_blocked.start, cur_blocked.start + cur_blocked.size()
                                );
                            /*critical bugfix here, was + nb.start before. Found this only because the assertion in the previous line failed.
                            Prior to the remapper refactor, we did not get the assert fail although we have been using the same memory layout.
                             */
                            self.next_ram_gpa += nb.size();
                            cur_blocked = nb;
                            self.next_blocked = next_device(&mut self.next_blocked_iter);
                        } else {
                            break;
                        }
                    }
                }
                self._total_ram_range_count += 1;
                if *remaining_chunk_bytes == 0 {
                    self.active_ram_range = None;
                }
                return Some(result);
            }
            // Device memory must be identity mapped, to pass through the access to the pyhsical HW
            ResourceKind::Device => {
                let dev_start = range.start;
                let dev_end = dev_start + range.size();

                let result = Segment {
                    hpa: dev_start,
                    gpa: dev_start,
                    size: range.size(),
                    repeat: 1,
                    next: None,
                };

                self.mapping_count += 1;
                self.highest_device_gpa = Some(GuestPhysAddr::new(match self.highest_device_gpa {
                    Some(v) => {
                        if v.as_usize() > dev_end {
                            v.as_usize()
                        } else {
                            dev_end
                        }
                    }
                    None => range.start + range.size(),
                }));
                self.active_ram_range = None;
                return Some(result);
            }
        } // end of "match resource_kind"
    }
}

pub fn new_compactified_mapping_iter<'a, T: MemoryColoring + Clone + Default>(
    permission_iter: PermissionIterator<'a, T>,
    start_ram_gpa: usize,
) -> CompatifiedMappingIter<'a, T> {
    /*let mut next_blocked_iter = permission_iter.clone().filter(|v| match v.resource_kind {
        ResourceKind::RAM(_) => false,
        ResourceKind::Device => true,
    });*/
    let mut next_blocked_iter = permission_iter.clone();

    let mut next_blocked = next_device(&mut next_blocked_iter);
    let first_ram_region = permission_iter
        .clone()
        .filter(|v| {
            ResourceKind::same_kind(&v.resource_kind, &ResourceKind::ram_with_all_partitions())
        })
        .next()
        .expect("memory region does not contain any resource kind RAM entries");

    let mut next_ram_gpa = start_ram_gpa;
    while let Some(nb) = next_blocked.as_ref() {
        if nb.start > first_ram_region.start {
            break;
        }
        next_ram_gpa += nb.end - nb.start;
        next_blocked = next_blocked_iter.next();
    }

    CompatifiedMappingIter {
        permission_iter,
        next_blocked_iter,
        next_blocked,
        next_ram_gpa,
        highest_device_gpa: None,
        _mapped_ram_bytes: 0,
        _mapped_device_bytes: 0,
        _total_ram_range_count: 0,
        mapping_count: 0,
        active_ram_range: None,
    }
}

impl<'a, T: MemoryColoring + Clone + Default> Default for CompatifiedMappingIter<'a, T> {
    fn default() -> Self {
        Self {
            permission_iter: Default::default(),
            next_blocked_iter: Default::default(),
            next_blocked: Default::default(),
            next_ram_gpa: Default::default(),
            highest_device_gpa: Default::default(),
            active_ram_range: Default::default(),
            _mapped_ram_bytes: Default::default(),
            _mapped_device_bytes: Default::default(),
            _total_ram_range_count: Default::default(),
            mapping_count: Default::default(),
        }
    }
}
