use std::path::PathBuf;
use std::process::abort;
use std::sync::atomic::Ordering;

use mmu::ptmapper::MAP_PAGE_TABLE;
use mmu::walker::{Level, WalkNext, Walker};
use mmu::{FrameAllocator, PtFlag, PtMapper};

use object::read::elf::ProgramHeader;
use object::{elf, Endianness};
use utils::{HostPhysAddr, HostVirtAddr};

use crate::allocator::{Allocator, BumpAllocator, ADDR_IDX, DEFAULT_BUMP_SIZE, PAGE_SIZE};
use crate::elf_modifier::{ModifiedELF, ModifiedSegment, TychePhdrTypes, DENDIAN};
use crate::instrument::{decode_map, MappingPageTables};

pub fn align_address(addr: usize) -> usize {
    if addr % PAGE_SIZE == 0 {
        return addr;
    }
    (PAGE_SIZE + addr) & !(PAGE_SIZE - 1)
}

#[cfg(not(feature = "riscv_enabled"))] 
fn translate_flags(flags: u32, segtype: u32) -> PtFlag {
    log::info!("x86_translate_flags");
    let mut ptflags: PtFlag; 
    ptflags = PtFlag::PRESENT;
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

#[cfg(feature = "riscv_enabled")] 
fn translate_flags(flags: u32, segtype: u32) -> PtFlag {
    log::info!("riscv_translate_flags");
    let mut ptflags: PtFlag;
    ptflags = PtFlag::VALID;  
    if flags & elf::PF_R == elf::PF_R {
        ptflags = ptflags.union(PtFlag::READ); 
    }
    if flags & elf::PF_W == elf::PF_W { 
        ptflags = ptflags.union(PtFlag::WRITE);
    }
    if flags & elf::PF_X == elf::PF_X { 
        ptflags = ptflags.union(PtFlag::EXECUTE);
    }
    //TODO: User flag is not enabled for now, should be enabled after TRT support is available for RV. 
    ptflags
}

//#[allow(dead_code)]   Neelu: Commenting.
pub fn generate_page_tables(
    melf: &ModifiedELF,
    map_page_tables: &Option<MappingPageTables>,
) -> (Vec<u8>, usize, usize) {
    let (map_op, virt_addr_start) = decode_map(map_page_tables);

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
            "The virtual offset is smaller than the memsz {:x} -- {:x}",
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

        log::debug!("virt addr {:#x}", virt.as_u64());
        log::debug!("phys addr {:#x}", curr_phys);
        log::debug!("size {:#x}", size);
        log::debug!("flags {:#x}", flags);

        mapper.map_range(&allocator, virt, HostPhysAddr::new(curr_phys), size, flags);
        curr_phys += size;
    }
    log::debug!(
        "Done mapping all the segments, we consummed {} extra pages",
        ADDR_IDX.load(Ordering::Relaxed)
    );
    if map_op {
        let mut virt_page_addr: usize = virt_addr_start;
        log::debug!("Now mapping the pages for page tables");
        let mut cnt = 0;
        while cnt < ADDR_IDX.load(Ordering::Relaxed) {
            let virt_addr = virt_page_addr;
            let phys_addr = curr_phys;
            let size: usize = PAGE_SIZE;
            log::debug!("virt addr {:#x}", virt_addr);
            log::debug!("phys addr {:#x}", phys_addr);
            log::debug!("size {:#x}", size);
            mapper.map_range(
                &allocator,
                HostVirtAddr::new(virt_addr),
                HostPhysAddr::new(phys_addr),
                size,
                MAP_PAGE_TABLE,
            );
            curr_phys += size;
            virt_page_addr += size;
            cnt += 1;
        }
    }
    log::debug!(
        "Done mapping all pages for the page tables, we consummed {} extra pages",
        bump.idx
    );
    // Transform everything into a vec array.
    let mut result: Vec<u8> = Vec::new();
    for i in 0..bump.idx {
        let page = &bump.pages[i].data;
        result.extend(page.to_vec());
    }
    (result, bump.idx, memsz)
}

pub struct Dumper<'a> {
    offset: usize,
    pages: &'a Vec<u8>,
}

unsafe impl Walker for Dumper<'_> {
    type PhysAddr = HostPhysAddr;
    type VirtAddr = HostVirtAddr;
    fn root(&mut self) -> (Self::PhysAddr, mmu::walker::Level) {
        (HostPhysAddr::new(self.offset), Level::L4)
    }
    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        let top = self.pages.as_ptr() as *const u64 as u64;
        let addr = phys_addr.as_u64() - self.offset as u64 + top;
        HostVirtAddr::new(addr as usize)
    }
}

pub fn print_page_tables(file: &PathBuf) {
    let data = std::fs::read(PathBuf::from(&file)).expect("Unable to read the binary");
    let elf = ModifiedELF::new(&data);
    let mut memsize: usize = 0;
    let mut pages: Vec<u8> = Vec::new();

    // Find page tables.
    for seg in &elf.segments {
        if seg.program_header.p_type(DENDIAN) != TychePhdrTypes::PageTablesConf as u32
            || seg.program_header.p_type(DENDIAN) != TychePhdrTypes::PageTablesSB as u32
        {
            if ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
                let mem = seg.program_header.p_memsz(Endianness::Little) as usize;
                let size = align_address(mem);
                memsize += size;
            }
            continue;
        }
        pages.extend(
            &seg.program_header
                .data(DENDIAN, &*data)
                .expect("Unable to read the data")
                .to_vec(),
        );
    }

    let mut dumper = Dumper {
        offset: memsize,
        pages: &pages,
    };

    let page_mask: usize = !(0x1000 - 1);
    unsafe {
        dumper
            .walk_range(
                HostVirtAddr::new(0),
                HostVirtAddr::new(align_address(elf.layout.max_addr as usize)),
                &mut |addr, entry, level| {
                    let flags = PtFlag::from_bits_truncate(*entry);
                    let phys = *entry & ((1 << 63) - 1) & (page_mask as u64);

#[cfg(not(feature = "riscv_enabled"))]
                    // Print if present
                    if flags.contains(PtFlag::PRESENT) {
                        let padding = match level {
                            Level::L4 => "",
                            Level::L3 => "  ",
                            Level::L2 => "    ",
                            Level::L1 => "      ",
                        };
                        log::info!(
                            "{}{:?} Virt: 0x{:x} - Phys: 0x{:x} - {:?}\n",
                            padding,
                            level,
                            addr.as_usize(),
                            phys,
                            flags
                        );
                        WalkNext::Continue
                    } else {
                        WalkNext::Leaf
                    }

#[cfg(feature = "riscv_enabled")]
                    // Print if present
                    if flags.contains(PtFlag::VALID) {
                        let padding = match level {
                            Level::L4 => "",
                            Level::L3 => "  ",
                            Level::L2 => "    ",
                            Level::L1 => "      ",
                        };
                        log::info!(
                            "{}{:?} Virt: 0x{:x} - Phys: 0x{:x} - {:?}\n",
                            padding,
                            level,
                            addr.as_usize(),
                            phys,
                            flags
                        );
                        WalkNext::Continue
                    } else {
                        WalkNext::Leaf
                    }

                },
            )
            .expect("Failed to dump pts");
    }
    log::info!("Survived everything");
}
