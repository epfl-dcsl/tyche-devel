use std::path::PathBuf;
use std::process::abort;
use std::sync::atomic::Ordering;

use mmu::ptmapper::MAP_PAGE_TABLE;
use mmu::walker::{Level, WalkNext, Walker};
use mmu::{FrameAllocator, PtFlag, PtMapper, RVPtFlag, RVPtMapper};
use object::read::elf::ProgramHeader;
use object::{elf, Endianness};
use utils::{HostPhysAddr, HostVirtAddr};

use crate::allocator::{Allocator, BumpAllocator, ADDR_IDX, DEFAULT_BUMP_SIZE, PAGE_SIZE};
use crate::elf_modifier::{ModifiedELF, ModifiedSegment, TychePhdrTypes, DENDIAN};
use crate::instrument::{decode_map, MappingPageTables};

pub fn align_address_up(addr: usize) -> usize {
    if addr % PAGE_SIZE == 0 {
        return addr;
    }
    (PAGE_SIZE + addr) & !(PAGE_SIZE - 1)
}

pub fn align_address_down(addr: usize) -> usize {
    if addr % PAGE_SIZE == 0 {
        return addr;
    }
    return (addr / PAGE_SIZE) * PAGE_SIZE;
}

enum FlagFormat {
    RV(RVPtFlag),
    X86(PtFlag),
}

enum Mapper {
    RVMapper(RVPtMapper<HostPhysAddr, HostVirtAddr>),
    X86Mapper(PtMapper<HostPhysAddr, HostVirtAddr>),
}

fn translate_flags(flags: u32, segtype: u32) -> PtFlag {
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
    if segtype == TychePhdrTypes::KernelPipe as u32 {
        ptflags = ptflags.union(PtFlag::PIPE);
    }
    ptflags
}

fn riscv_translate_flags(flags: u32, segtype: u32) -> RVPtFlag {
    let mut ptflags: RVPtFlag;
    ptflags = RVPtFlag::VALID;
    if flags & elf::PF_R == elf::PF_R {
        ptflags = ptflags.union(RVPtFlag::READ);
    }
    if flags & elf::PF_W == elf::PF_W {
        ptflags = ptflags.union(RVPtFlag::WRITE);
    }
    if flags & elf::PF_X == elf::PF_X {
        ptflags = ptflags.union(RVPtFlag::EXECUTE);
    }
    //TODO: User flag is not enabled for now, should be enabled after TRT support is available for RV.
    if segtype == TychePhdrTypes::KernelPipe as u32 {
        ptflags = ptflags.union(RVPtFlag::PIPE);
    }
    ptflags
}

pub fn generate_page_tables(
    melf: &ModifiedELF,
    map_page_tables: &Option<MappingPageTables>,
    riscv_enabled: bool,
) -> (Vec<u8>, usize, usize) {
    let (map_op, virt_addr_start) = decode_map(map_page_tables);

    // Compute the overall memory required for the binary.
    let mut memsz: usize = 0;
    for ph in &melf.segments {
        let segtype = ph.program_header.p_type(Endianness::Little);
        if !ModifiedSegment::is_loadable(segtype) || segtype == TychePhdrTypes::KernelPipe as u32 {
            continue;
        }
        let mem = ph.program_header.p_memsz(Endianness::Little) as usize;
        let size = align_address_up(mem);
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
    let mut mapper: Mapper = if !riscv_enabled {
        Mapper::X86Mapper(PtMapper::<HostPhysAddr, HostVirtAddr>::new(
            offset,
            0,
            root.phys_addr,
        ))
    } else {
        Mapper::RVMapper(RVPtMapper::<HostPhysAddr, HostVirtAddr>::new(
            offset,
            0,
            root.phys_addr,
        ))
    };
    let mut curr_phys: usize = 0;
    let mut curr_phys_pipe: usize = 0;
    for ph in &melf.segments {
        let segtype = ph.program_header.p_type(Endianness::Little);
        if !ModifiedSegment::is_loadable(segtype) {
            continue;
        }
        let mem_size = ph.program_header.p_memsz(Endianness::Little) as usize;
        let vaddr = align_address_down(ph.program_header.p_vaddr(Endianness::Little) as usize);
        let virt = HostVirtAddr::new(vaddr);
        let size = align_address_up(mem_size);
        let flags: FlagFormat = if !riscv_enabled {
            FlagFormat::X86(translate_flags(
                ph.program_header.p_flags(Endianness::Little),
                segtype,
            ))
        } else {
            FlagFormat::RV(riscv_translate_flags(
                ph.program_header.p_flags(Endianness::Little),
                segtype,
            ))
        };
        let phys_addr = if segtype == TychePhdrTypes::KernelPipe as u32 {
            HostPhysAddr::new(curr_phys_pipe)
        } else {
            HostPhysAddr::new(curr_phys)
        };
        match flags {
            FlagFormat::RV(rv_flags) => {
                //We could remove the flags match by making map_range do the flag translation - but
                //then the mmu lib needs to understand the elf flags format.
                match mapper {
                    Mapper::RVMapper(ref mut rv_mapper) => {
                        rv_mapper.map_range(&allocator, virt, phys_addr, size, rv_flags);
                    }
                    Mapper::X86Mapper(_) => {
                        log::error!(
                            "The mapper and flags are created for different architectures."
                        );
                        abort();
                    }
                }
            }
            FlagFormat::X86(x86_flags) => match mapper {
                Mapper::X86Mapper(ref mut x86_mapper) => {
                    x86_mapper.map_range(&allocator, virt, phys_addr, size, x86_flags);
                }
                Mapper::RVMapper(_) => {
                    log::error!("The mapper and flags are created for different architectures.");
                    abort();
                }
            },
        }
        if segtype != TychePhdrTypes::KernelPipe as u32 {
            curr_phys += size;
        } else {
            curr_phys_pipe += size;
        }
    }
    log::debug!(
        "Done mapping all the segments, we consummed {} extra pages",
        ADDR_IDX.load(Ordering::Relaxed)
    );
    if !riscv_enabled {
        if map_op {
            let mut virt_page_addr: usize = virt_addr_start;
            log::debug!("Now mapping the pages for page tables");
            let mut cnt = 0;
            while cnt < ADDR_IDX.load(Ordering::Relaxed) {
                let virt_addr = virt_page_addr;
                let phys_addr = curr_phys;
                let size: usize = PAGE_SIZE;

                match mapper {
                    Mapper::X86Mapper(ref mut x86_mapper) => {
                        x86_mapper.map_range(
                            &allocator,
                            HostVirtAddr::new(virt_addr),
                            HostPhysAddr::new(phys_addr),
                            size,
                            MAP_PAGE_TABLE,
                        );
                    }
                    Mapper::RVMapper(_) => {
                        log::error!(
                            "The mapper hasn't been created for the expected architecture."
                        );
                        abort();
                    }
                }

                curr_phys += size;
                virt_page_addr += size;
                cnt += 1;
            }
            log::debug!(
                "Done mapping all pages for the page tables, we consummed {} extra pages",
                bump.idx
            );
        }
    }
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
    fn get_phys_addr(_: u64) -> <Self as Walker>::PhysAddr {
        todo!()
    }
}

pub fn print_page_tables(file: &PathBuf, riscv_enabled: bool) {
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
                let size = align_address_up(mem);
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
                HostVirtAddr::new(align_address_up(elf.layout.max_addr as usize)),
                &mut |addr, entry, level| {
                    let phys = *entry & ((1 << 63) - 1) & (page_mask as u64);

                    if !riscv_enabled {
                        let flags = PtFlag::from_bits_truncate(*entry);
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
                    } else {
                        let flags = RVPtFlag::from_bits_truncate(*entry);
                        // Print if present
                        if flags.contains(RVPtFlag::VALID) {
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
                    }
                },
            )
            .expect("Failed to dump pts");
    }
    log::info!("Survived everything");
}
