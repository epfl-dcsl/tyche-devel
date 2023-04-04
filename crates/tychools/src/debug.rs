use std::path::PathBuf;

use elfloader::*;
use log::info;
use mmu::walker::Level;
use mmu::{FrameAllocator, PtFlag, PtMapper};
use utils::{HostPhysAddr, HostVirtAddr};
use xmas_elf::program::Type;

use crate::allocator::{Allocator, BumpAllocator, PAGE_SIZE};

pub fn print_elf_segments(path: &PathBuf) {
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let binary = ElfBinary::new(slice).expect("Unable to parse elf.");
    for ph in binary.program_headers() {
        info!(
            "base = {:#x} size = {:#x} type = {:?} flags = {}",
            ph.virtual_addr(),
            ph.mem_size(),
            ph.get_type().unwrap(),
            ph.flags()
        );
    }
}

fn align_address(addr: usize) -> usize {
    if addr % PAGE_SIZE == 0 {
        return addr;
    }
    (PAGE_SIZE + addr) & !(PAGE_SIZE - 1)
}

fn translate_flags(flags: Flags) -> PtFlag {
    let mut ptflags: PtFlag = PtFlag::PRESENT;
    if flags.is_write() {
        ptflags = ptflags.union(PtFlag::WRITE);
    }
    if !flags.is_execute() {
        ptflags = ptflags.union(PtFlag::EXEC_DISABLE);
    }
    ptflags
}

/// Attempt to build page tables for the binary and just dump them on the screen for now.
pub fn print_page_tables(path: &PathBuf) {
    let file_data = std::fs::read(path).expect("Could not read file");
    let slice = file_data.as_slice();
    let binary = ElfBinary::new(slice).expect("Unable to parse elf.");

    // Compute the overall memory necessary to host the entire binary.
    let mut mem_size: usize = 0;
    for ph in binary.program_headers() {
        if ph.get_type().unwrap() != Type::Load {
            continue;
        }
        let mem = ph.mem_size() as usize;
        let size = align_address(mem);
        mem_size += size;
    }
    println!("The mem_size is {:x} bytes!", mem_size);

    // We know how much memory is needed for loadable segments.
    // The page table offset is thus known and we can start building them now.
    let mut bump = BumpAllocator::<500>::new(mem_size);
    if bump.get_virt_offset() < mem_size {
        panic!("Oups, the virt_offset is smaller than the mem_size");
    }
    let offset = bump.get_virt_offset() - mem_size;
    let allocator = Allocator::new(&mut bump);
    let root = allocator.allocate_frame().unwrap();
    let mut mapper = PtMapper::<HostPhysAddr, HostVirtAddr>::new(offset, 0, root.phys_addr);
    let mut curr_phys: usize = 0;
    for ph in binary.program_headers() {
        if ph.get_type().unwrap() != Type::Load {
            continue;
        }
        let mem_size = ph.mem_size() as usize;
        let virt = HostVirtAddr::new(ph.virtual_addr() as usize);
        let size: usize = align_address(mem_size);
        let flags = translate_flags(ph.flags());
        mapper.map_range(&allocator, virt, HostPhysAddr::new(curr_phys), size, flags);
        curr_phys += size;
    }
    /*println!("Done mapping, we consumed {} extra pages", bump.idx);
    mapper.debug_range(HostVirtAddr::new(0x400000), 0x5000, Level::L1, |args| {
        println!("{}", args.to_string());
    })*/
}
