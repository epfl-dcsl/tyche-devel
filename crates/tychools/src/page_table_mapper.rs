use std::process::abort;

use mmu::{FrameAllocator, PtFlag, PtMapper};
use object::read::elf::ProgramHeader;
use object::{elf, Endianness};
use utils::{HostPhysAddr, HostVirtAddr};

use crate::allocator::{Allocator, BumpAllocator, DEFAULT_BUMP_SIZE, PAGE_SIZE};
use crate::elf_modifier::{ModifiedELF, ModifiedSegment, TychePhdrTypes};

fn align_address(addr: usize) -> usize {
    if addr % PAGE_SIZE == 0 {
        return addr;
    }
    (PAGE_SIZE + addr) & !(PAGE_SIZE - 1)
}

fn translate_flags(flags: u32, segtype: u32) -> PtFlag {
    let mut ptflags: PtFlag = PtFlag::PRESENT;
    if flags & elf::PF_W == elf::PF_W {
        ptflags = ptflags.union(PtFlag::WRITE);
    }
    if flags & elf::PF_X == 0 {
        ptflags = ptflags.union(PtFlag::EXEC_DISABLE);
    }
    if TychePhdrTypes::is_user(segtype) {
        ptflags = ptflags.union(PtFlag::USER);
    }
    ptflags
}

#[allow(dead_code)]
pub fn generate_page_tables(melf: &ModifiedELF) -> (Vec<u8>, usize) {
    // Compute the overall memory required for the binary.
    let mut memsz: usize = 0;
    for ph in &melf.segments {
        let segtype = ph.program_header.p_type(Endianness::Little);
        if !ModifiedSegment::is_loadable(segtype) {
            continue;
        }
        let mem = ph.program_header.p_memsz(Endianness::Little) as usize;
        let size = align_address(mem);
        memsz += size;
    }
    log::debug!("Computed size for the binary is {:x}", memsz);

    // Pages for the page table start at phys_addr == memsz;
    let mut bump = BumpAllocator::<DEFAULT_BUMP_SIZE>::new(memsz);
    if bump.get_virt_offset() < memsz {
        log::error!(
            "The virtual offset is smaller thant he memsz {:x} -- {:x}",
            bump.get_virt_offset(),
            memsz
        );
        abort();
    }
    let offset = bump.get_virt_offset() - memsz;
    let allocator = Allocator::new(&mut bump);
    let root = allocator.allocate_frame().unwrap();
    let mut mapper = PtMapper::<HostPhysAddr, HostVirtAddr>::new(offset, 0, root.phys_addr);
    let mut curr_phys: usize = 0;
    for ph in &melf.segments {
        let segtype = ph.program_header.p_type(Endianness::Little);
        if !ModifiedSegment::is_loadable(segtype) {
            continue;
        }
        let mem_size = ph.program_header.p_memsz(Endianness::Little) as usize;
        let vaddr = ph.program_header.p_vaddr(Endianness::Little) as usize;
        let virt = HostVirtAddr::new(vaddr);
        let size = align_address(mem_size);
        let flags = translate_flags(ph.program_header.p_flags(Endianness::Little), segtype);
        mapper.map_range(&allocator, virt, HostPhysAddr::new(curr_phys), size, flags);
        curr_phys += size;
    }
    log::debug!(
        "Done mapping all the segments, we consummed {} extra pages",
        bump.idx
    );
    // Transform everything into a vec array.
    let mut result: Vec<u8> = Vec::new();
    for i in 0..bump.idx {
        let page = &bump.pages[i].data;
        result.extend(page.to_vec());
    }
    (result, bump.idx)
}
