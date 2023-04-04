use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use elfloader::*;
use log::{debug, error, info};
use mmu::{FrameAllocator, PtFlag, PtMapper};
use utils::{HostPhysAddr, HostVirtAddr};
use xmas_elf::program::Type;

use crate::allocator::{Allocator, BumpAllocator, DEFAULT_BUMP_SIZE, PAGE_SIZE};

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
pub fn dump_page_tables(src: &PathBuf, dest: &PathBuf) {
    // Check if the dest file exists.
    if dest.exists() {
        error!("The file {:?} already exists!", dest);
        return;
    }

    // Read the file.
    let file_data = match std::fs::read(src) {
        Err(e) => {
            error!("Unable to read {:?} : {}", dest, e);
            return;
        }
        Ok(v) => v,
    };
    let slice = file_data.as_slice();

    // Parse the binary.
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

    debug!(
        "{:?} requires {:?} bytes of memory for the segments.",
        dest, mem_size
    );

    // Pages for the page table start at phys_addr offset == mem_size.
    let mut bump = BumpAllocator::<DEFAULT_BUMP_SIZE>::new(mem_size);
    if bump.get_virt_offset() < mem_size {
        error!(
            "The virtual offset is smaller than the mem_size {:x} -- {:x}",
            bump.get_virt_offset(),
            mem_size
        );
        return;
    }
    // Converting fake phys_addr to virt_addr by adding this offset.
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

    debug!(
        "Done mapping all the segments from {:?}, we consumed {} extra pages!",
        src, bump.idx
    );

    // Dump the content of page tables as a new segmen in the binary.
    let mut file = match OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(dest)
    {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to reopen the file {:?}: {}", dest, e);
            return;
        }
    };

    /*
    let elf = match Elf::parse(&mut slice) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to parse the elf {:?} : {}", dest, e);
            return;
        }
    };

    // Add a new program header to the file.
    let new_phdr = program_header::ProgramHeader {
        p_type: program_header::PT_NOTE,
        p_offset: elf.program_headers.last().unwrap().p_offset
            + elf.program_headers.last().unwrap().p_filesz,
        p_vaddr: elf.program_headers.last().unwrap().p_vaddr
            + elf.program_headers.last().unwrap().p_memsz,
        p_paddr: bump.phys_offset as u64,
        p_filesz: (bump.idx * PAGE_SIZE) as u64,
        p_memsz: (bump.idx * PAGE_SIZE) as u64,
        p_flags: program_header::PF_R,
        p_align: PAGE_SIZE as u64,
    };

    elf.program_headers.push(new_phdr.clone());

    // Update the ELF header to contain the new segment.
    elf.header.e_phnum += 1;
    elf.header.e_shoff = new_phdr.p_filesz;
    elf.header.e_phoff += phdr64::program_header64::SIZEOF_PHDR as u64;

    if let Err(e) = file.seek(SeekFrom::Start(0)) {
        error!("Unable to seek the begining of {:?}: {}", dest, e);
        return;
    }
    match elf.write() {
        Ok(v) => {
            if let Err(e) = file.write_all(v) {
                error!("Unable to write the headers to {:?} : {}", dest, e);
                return;
            }
        }
        Err(e) => {
            error!("Unable to convert the elf into a vector: {}", e);
            return;
        }
    }

    // Now write the extra segment.
    if let Err(e) = file.seek(SeekFrom::End(0)) {
        error!("Unable to reach the end of the file {:?} : {}", file, e);
        return;
    }
    */

    // Add the content to the file.
    // First write the offset.
    if let Err(e) = file.write(&bump.phys_offset.to_ne_bytes()) {
        error!("Unable to write the size to {:?}: {}", dest, e);
        return;
    }
    for i in 0..bump.idx {
        if let Err(e) = file.write(&bump.pages[i].data) {
            error!("Unable to write {}th page to {:?}: {}", i, dest, e);
            return;
        }
    }
    info!(
        "The binary {:?} page tables have been generated and dumped into {:?}",
        src, dest
    );
}
