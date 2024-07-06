use alloc::vec::Vec;
use core::cmp::min;

use mmu::frame_allocator::PhysRange;
use mmu::ioptmapper::PAGE_MASK;
use mmu::RangeAllocator;
use vmx::HostPhysAddr;
use x86_64::{align_down, align_up};

use super::{ElfProgram, NonContigElf64Phdr};
use crate::elf::Elf64PhdrType;
use crate::mmu::PAGE_SIZE;

/// Relocates the physical addresses of an elf program.
pub fn relocate_elf(
    elf: &mut ElfProgram,
    allocator: &impl RangeAllocator,
    force_seek_allocator: bool,
) {
    log::info!(
        "relocate_elf: force_seek_allocator? {}",
        force_seek_allocator
    );
    let mut all_allocated_mem = Vec::new();

    let mut prev_segment: Option<&NonContigElf64Phdr> = None;
    for segment in &mut elf.segments {
        if segment.phdr.p_type != Elf64PhdrType::PT_LOAD.bits() {
            continue;
        }
        let mut aligned_size = align_up(segment.phdr.p_memsz, PAGE_SIZE as u64) as usize;
        log::info!(
            "relocate_elf : segment paddr 0x{:x}, size 0x{:x}, aligned_size 0x{:x}",
            segment.phdr.p_paddr,
            segment.phdr.p_memsz,
            aligned_size
        );

        let mut ranges: Vec<PhysRange> = Vec::new();

        /*
           Luca Wilke:
           For some reason, LOAD segments often share a common page with their preceeding segment.
           At least the tyche binary is missing reloaction information, so we cannot easily move the segments apart
           without breaking memory references from .text to .rodata, .got, .data etc.
           For now, we simply make sure that if there is an overlap, we use the same physical page in the current segment
           than in the prev segment
           This might lead to a clash with the requested page permissions but so far we have been lucky
        */
        //
        if let Some(prev_segment) = prev_segment {
            let cur_aligned_start = align_down(segment.phdr.p_vaddr, PAGE_SIZE as u64);
            let prev_aligned_end = align_down(
                prev_segment.phdr.p_vaddr + prev_segment.phdr.p_memsz,
                PAGE_SIZE as u64,
            );
            //in case of overlap, we need to allocate less memory later on, due to the shared page
            if cur_aligned_start == prev_aligned_end {
                if force_seek_allocator {
                    panic!("overlap with force seeek");
                }
                //reuse last page from prev segment as first page for this segment
                let prev_last_range = prev_segment
                    .phys_mem
                    .last()
                    .expect("prev segment has empty phys_mem");
                let overlapping_page =
                    HostPhysAddr::new(prev_last_range.end.as_usize() - PAGE_SIZE);
                let overlapping_pr = PhysRange {
                    start: overlapping_page,
                    end: overlapping_page + PAGE_SIZE,
                };
                assert!(overlapping_pr.start < overlapping_pr.end);
                ranges.push(overlapping_pr);
                //number of bytes on shared page
                //TODO: double check the mask calculation with a print
                let size_adjust = min(
                    PAGE_SIZE - (segment.phdr.p_paddr as usize & PAGE_MASK),
                    segment.phdr.p_memsz as usize,
                );
                log::info!(
                    "size_adjust: 0x{:x}, memsz 0x{:x}",
                    size_adjust,
                    segment.phdr.p_memsz
                );
                let old_aligned_size = aligned_size;
                aligned_size =
                    align_up(segment.phdr.p_memsz - size_adjust as u64, PAGE_SIZE as u64) as usize;
                log::info!("updating aligned size. prev value 0x:{:x}, bytes used on shared page {:x}, new aligned size 0x{:x}",
            old_aligned_size, size_adjust, aligned_size);
            }
            if aligned_size > 0 {
                if force_seek_allocator {
                    let cur_next_gpa = allocator.gpa_of_next_allocation().as_usize();
                    let want_for_next_gpa = segment.phdr.p_paddr as usize;

                    if cur_next_gpa < want_for_next_gpa {
                        let diff = want_for_next_gpa - cur_next_gpa;
                        log::info!("force seeking allocator: cur_next_gpa {:x}, want {:x}, seeking {:x} bytes which equals {} pages",
                        cur_next_gpa, want_for_next_gpa, diff,diff/PAGE_SIZE);
                        //we cannot do range allocation here as jumping over blocked ranges or gaps affects
                        //our next gpa in hard to precalculate ways
                        while allocator.gpa_of_next_allocation().as_usize() < want_for_next_gpa {
                            allocator.allocate_frame();
                        }
                    } else if cur_next_gpa > want_for_next_gpa {
                        panic!("force_seek allocator ant cur_next gpa is past want gpa, cannot go back");
                    }
                    assert_eq!(
                        want_for_next_gpa,
                        allocator.gpa_of_next_allocation().as_usize(),
                        "Wanted to seek to next_gpa 0x{:x}, got 0x{:x}",
                        want_for_next_gpa,
                        allocator.gpa_of_next_allocation().as_usize()
                    );
                }
                //allocate remaining memory
                let store_cb = |pr: PhysRange| {
                    ranges.push(pr);
                };
                allocator
                    .allocate_range(aligned_size, store_cb)
                    .expect("failed to alloc mem for segment");
            }
        } else {
            if force_seek_allocator {
                let cur_next_gpa = allocator.gpa_of_next_allocation().as_usize();
                let want_for_next_gpa = segment.phdr.p_paddr as usize;

                if cur_next_gpa < want_for_next_gpa {
                    let diff = want_for_next_gpa - cur_next_gpa;
                    log::info!("force seeking allocator: cur_next_gpa {:x}, want {:x}, seeking {:x} bytes which equals {} pages",
                    cur_next_gpa, want_for_next_gpa, diff,diff/PAGE_SIZE);
                    //we cannot do range allocation here as jumping over blocked ranges or gaps affects
                    //our next gpa in hard to precalculate ways
                    while allocator.gpa_of_next_allocation().as_usize() < want_for_next_gpa {
                        allocator.allocate_frame();
                    }
                } else if cur_next_gpa > want_for_next_gpa {
                    panic!(
                        "force_seek allocator ant cur_next gpa is past want gpa, cannot go back"
                    );
                }
                assert_eq!(
                    want_for_next_gpa,
                    allocator.gpa_of_next_allocation().as_usize(),
                    "Wanted to seek to next_gpa 0x{:x}, got 0x{:x}",
                    want_for_next_gpa,
                    allocator.gpa_of_next_allocation().as_usize()
                );
            }
            //not prev segment, just allocate memory
            let store_cb = |pr: PhysRange| {
                ranges.push(pr);
            };
            allocator
                .allocate_range(aligned_size, store_cb)
                .expect("failed to alloc mem for segment");
        }
        segment.phys_mem = ranges;
        log::info!("segment relocated. ranges {:x?}", &segment.phys_mem);

        all_allocated_mem.push(segment.phys_mem.clone());
        prev_segment = Some(segment);
    }
}
