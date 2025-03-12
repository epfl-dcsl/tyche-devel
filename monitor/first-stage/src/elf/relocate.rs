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

fn seek_allocator(allocator: &impl RangeAllocator, want_for_next_gpa: usize) {
    let cur_next_gpa = allocator.gpa_of_next_allocation().as_usize();

    if cur_next_gpa < want_for_next_gpa {
        //we cannot do range allocation here as jumping over blocked ranges or gaps affects
        //our next gpa in hard to precalculate ways
        //TODO: luca: Maybe add a seek directly to the allocator to avoid repeatedly allocating single frames?
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

/// Relocates the physical addresses of an elf program.
/// # Arguments
/// - `force_seek_allocator` : If true, allocate mem from allocator until next gpa equals the p_paddr
/// from the next elf segment. We use this to load stuff to the address where the EPT builder in stage2
/// will eventually map it to
pub fn relocate_elf(
    elf: &mut ElfProgram,
    allocator: &impl RangeAllocator,
    force_seek_allocator: bool,
) {

    let mut prev_segment: Option<&NonContigElf64Phdr> = None;
    for segment in &mut elf.segments {
        if segment.phdr.p_type != Elf64PhdrType::PT_LOAD.bits() {
            continue;
        }
        let mut aligned_size = align_up(segment.phdr.p_memsz, PAGE_SIZE as u64) as usize;

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
                let size_adjust = min(
                    PAGE_SIZE - (segment.phdr.p_paddr as usize & PAGE_MASK),
                    segment.phdr.p_memsz as usize,
                );
                aligned_size =
                    align_up(segment.phdr.p_memsz - size_adjust as u64, PAGE_SIZE as u64) as usize;
            }
            if aligned_size > 0 {
                if force_seek_allocator {
                    let want_for_next_gpa = segment.phdr.p_paddr as usize;
                    seek_allocator(allocator, want_for_next_gpa);
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
                if force_seek_allocator {
                    let want_for_next_gpa = segment.phdr.p_paddr as usize;
                    seek_allocator(allocator, want_for_next_gpa);
                }
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

        prev_segment = Some(segment);
    }
}
