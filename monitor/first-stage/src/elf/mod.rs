//! Executable and Linkable Format - ELF

mod ffi;
pub mod relocate;

use alloc::vec::Vec;
use core::str::from_utf8;

pub use ffi::{
    Elf64Hdr, Elf64Phdr, Elf64PhdrFlags, Elf64PhdrType, Elf64Shdr, Elf64ShdrType, Elf64Sym,
    FromBytes,
};
use mmu::frame_allocator::PhysRange;
use mmu::guest_ptmapper::GuestPtMapper;
use mmu::ioptmapper::{PAGE_MASK, PAGE_SIZE};
use mmu::ptmapper::DEFAULT_PROTS;
use mmu::walker::Address;
use mmu::{PtFlag, PtMapper, RangeAllocator};
use vmx::HostPhysAddr;
use x86_64::VirtAddr;

use crate::mmu::scattered_writer::ScatteredIdMappedBuf;
use crate::{GuestPhysAddr, GuestVirtAddr, HostVirtAddr};

// Wrapper struct that stores a `NonContigElf64Phdr` togher with the (possibly scattered) memory ranges
// that we will map it to.
// We also use this for non-loadable segments and simply ignore that they will never be loaded to mem
#[derive(Debug)]
pub struct NonContigElf64Phdr {
    pub phdr: Elf64Phdr,
    //physical memory for this phdr. Defaults to [phdr.paddr,phdr.paddr+phdr.p_memsz[
    pub phys_mem: Vec<PhysRange>,
}

impl From<Elf64Phdr> for NonContigElf64Phdr {
    fn from(value: Elf64Phdr) -> Self {
        let mut phys_mem = Vec::new();
        phys_mem.push(PhysRange {
            start: HostPhysAddr::new(value.p_paddr as usize),
            end: HostPhysAddr::new((value.p_paddr + value.p_memsz) as usize),
        });
        Self {
            phdr: value,
            phys_mem,
        }
    }
}

pub enum ElfMapping {
    /// Respect the virtual-to-physical mapping of the ELF file.
    ElfDefault,
    /// Use an identity mapping, i.e. virtual addresses becomes equal to physical addresses.
    Identity,
    ///Map virt to phys using scattered physical memory, as it is the case for coloring
    Scattered,
    ///Testing possible bug with linux mapping
    ScatteredPaddr,
}

/// An ELF program that can be loaded as a guest.
pub struct ElfProgram {
    /// The entry point, as a guest virtual address.
    pub entry: GuestVirtAddr,
    /// The entry point, as a guest physical address.
    /// To be used with identity mapping.
    pub phys_entry: GuestPhysAddr,
    pub segments: Vec<NonContigElf64Phdr>,
    pub sections: Vec<Elf64Shdr>,
    /// Raw Elf binary
    pub bytes: &'static [u8],
    mapping: ElfMapping,
}

pub enum ELfTargetEnvironment {
    Host(PtMapper<HostPhysAddr, HostVirtAddr>),
    Guest(GuestPtMapper<GuestPhysAddr, GuestVirtAddr>),
}

pub struct LoadedElf {
    /// Offset in the host, used to load the guest into memory.
    host_physical_offset: usize,
    /// The page table mapper of the guest.
    pub pt_mapper: ELfTargetEnvironment,
    //_virt: PhantomData<VirtAddr>,
    //_phys: PhantomData<PhysAddr>,
}

impl ElfProgram {
    /// Parses an elf program from raw bytes.
    ///
    /// Uses the ELF virtual-to-physical mappings by default.
    pub fn new(bytes: &'static [u8]) -> Self {
        let mut start: usize = 0;
        let mut end: usize = Elf64Hdr::SIZE;
        let header = Elf64Hdr::from_bytes(&bytes[start..end]).expect("header");

        // Parse all the program header entries.
        start = header.e_phoff as usize;
        end = start + (header.e_phentsize as usize);
        let mut prog_headers = Vec::<Elf64Phdr>::new();
        for _i in 0..header.e_phnum {
            let pheader = Elf64Phdr::from_bytes(&bytes[start..end]).expect("parsing prog header");
            prog_headers.push(pheader);
            start = end;
            end += header.e_phentsize as usize;
        }

        // Find entry virtual address
        let mut entry = None;
        let phys_entry = header.e_entry;
        for header in &prog_headers {
            let segment_start = header.p_paddr;
            let segment_end = segment_start + header.p_memsz;
            if phys_entry >= segment_start && phys_entry < segment_end {
                let segment_offset = phys_entry - segment_start;
                entry = Some(header.p_vaddr + segment_offset);
            }
        }
        let entry = entry.expect("Couldn't find guest entry point");

        // Parse section header table: this is needed to access symbols.
        let mut sections = Vec::<Elf64Shdr>::new();
        let shdr_start = header.e_shoff as usize;
        assert!(header.e_shentsize as usize == Elf64Shdr::SIZE);
        for i in 0..header.e_shnum {
            let start = shdr_start + (i as usize) * Elf64Shdr::SIZE;
            let end = start + Elf64Shdr::SIZE;
            let section =
                Elf64Shdr::from_bytes(&bytes[start..end]).expect("parsing section header");
            sections.push(section);
        }

        Self {
            entry: GuestVirtAddr::new(entry as usize),
            phys_entry: GuestPhysAddr::new(phys_entry as usize),
            segments: prog_headers.into_iter().map(|v| v.into()).collect(),
            sections,
            mapping: ElfMapping::ElfDefault,
            bytes,
        }
    }

    /// Configures the mappings for this program.
    pub fn set_mapping(&mut self, mapping: ElfMapping) {
        self.mapping = mapping;
    }

    /// Load the program and set up a new set PtMapper structure for it
    ///
    /// On success, returns the guest physical address of the guest page table root (to bet set as
    /// CR3).
    pub fn load(
        &self,
        allocator: &impl RangeAllocator,
        host_physical_offset: usize,
        build_gpa_pts: bool,
    ) -> Result<LoadedElf, ()> {
        let mut pts_target_env: ELfTargetEnvironment = if build_gpa_pts {
            let inner_spa_pt_root = allocator.allocate_frame().ok_or(())?.zeroed();
            let mut inner_pt_mapper = PtMapper::<HostPhysAddr, GuestPhysAddr>::new(
                host_physical_offset,
                0,
                inner_spa_pt_root.phys_addr,
            );

            let gpa_pt_root = allocator.gpa_of_next_allocation();
            let spa_pt_root = allocator.allocate_frame().ok_or(())?.zeroed();
            inner_pt_mapper.map_range(
                allocator,
                gpa_pt_root,
                spa_pt_root.phys_addr,
                PAGE_SIZE,
                DEFAULT_PROTS,
            );

            let pt_mapper = GuestPtMapper::new(gpa_pt_root, inner_pt_mapper);
            ELfTargetEnvironment::Guest(pt_mapper)
        } else {
            let pt_root = allocator.allocate_frame().ok_or(())?.zeroed();
            let pt_root_guest_phys_addr = HostPhysAddr::from_usize(pt_root.phys_addr.as_usize());
            let pt_mapper = PtMapper::<HostPhysAddr, HostVirtAddr>::new(
                host_physical_offset,
                0,
                pt_root_guest_phys_addr,
            );
            ELfTargetEnvironment::Host(pt_mapper)
        };

        // Load and map segments
        for seg in self.segments.iter() {
            if seg.phdr.p_type != Elf64PhdrType::PT_LOAD.bits() {
                // Skip non-load segments.
                continue;
            }
            unsafe {
                // TODO: ensure that the segment does not overlap host memory
                self.load_segment(seg, HostVirtAddr::new(host_physical_offset));
                self.map_segment(seg, &mut pts_target_env, allocator);
            }
        }

        Ok(LoadedElf {
            pt_mapper: pts_target_env,
            host_physical_offset,
        })
    }

    pub fn find_symbol(&self, target: &str) -> Option<Elf64Sym> {
        if self.sections.len() == 0 {
            return None;
        }
        let symbols_secs = self.find_section(Elf64ShdrType::SHT_SYMTAB);
        let strings = self.find_section(Elf64ShdrType::SHT_STRTAB);
        for sym in symbols_secs.iter() {
            for str_values in strings.iter() {
                if let Some(symbol) = self.find_symbol_helper(target, sym, str_values) {
                    return Some(symbol);
                }
            }
        }
        return None;
    }

    pub fn find_symbol_helper(
        &self,
        target: &str,
        symbols: &Elf64Shdr,
        strings: &Elf64Shdr,
    ) -> Option<Elf64Sym> {
        if self.sections.len() == 0 {
            return None;
        }

        // Find the symbol table sections.
        //let symbols = self.find_section(Elf64ShdrType::SHT_SYMTAB)?;

        // Find the string table.
        // This could be obtained directly from elf header.
        //let strings = self.find_section(Elf64ShdrType::SHT_STRTAB)?;

        let str_start = strings.sh_offset as usize;
        let str_end = str_start + strings.sh_size as usize;
        let content = &self.bytes[str_start..str_end];

        // Now look for the symbol
        if symbols.sh_size == 0 || symbols.sh_entsize == 0 {
            return None;
        }
        assert!(symbols.sh_entsize as usize == Elf64Sym::SIZE);
        // Read all the entries now.
        let nb = symbols.sh_size / symbols.sh_entsize;
        let off = symbols.sh_offset;
        for i in 0..nb {
            let start = (off + i * symbols.sh_entsize) as usize;
            let end = start + symbols.sh_entsize as usize;
            let symbol = Elf64Sym::from_bytes(&self.bytes[start..end]).expect("parsing symbol");
            if symbol.st_name == 0 || symbol.st_name as usize > content.len() {
                continue;
            }
            let n_start = symbol.st_name as usize;
            let idx = self.find_substring(&content[n_start..])?;
            let name = from_utf8(&content[n_start..(n_start + idx)]).expect("parsing name");
            // Now find the name for this symbol.
            if name == target {
                return Some(symbol);
            }
        }
        return None;
    }

    fn find_substring(&self, content: &[u8]) -> Option<usize> {
        for (i, &v) in content.iter().enumerate() {
            if v == b'\0' {
                return Some(i);
            }
        }
        return None;
    }

    fn find_section(&self, tpe: Elf64ShdrType) -> Vec<&Elf64Shdr> {
        let mut result = Vec::<&Elf64Shdr>::new();
        for sec in self.sections.iter() {
            if sec.sh_type == tpe.bits() {
                result.push(&sec);
            }
        }
        return result;
    }

    /// Maps an elf segment at the desired virtual address.
    /// # Arguments
    /// - `mapper` page table "abstractions" to which the mappins are added
    /// - `allocator` : mostly used to allocate memory for page table entires
    pub unsafe fn map_segment(
        &self,
        segment: &NonContigElf64Phdr,
        mapping_env: &mut ELfTargetEnvironment,
        allocator: &impl RangeAllocator,
    ) {
        let align_page_down = |addr: u64| addr & !(PAGE_SIZE as u64 - 1);
        let p_vaddr = align_page_down(segment.phdr.p_vaddr);

        let mut memsz = segment.phdr.p_memsz;
        if p_vaddr != segment.phdr.p_vaddr {
            memsz += segment.phdr.p_vaddr - p_vaddr;
        }

        assert!(p_vaddr % PAGE_SIZE as u64 == 0);
        assert!(segment.phys_mem[0].start.as_usize() % PAGE_SIZE == 0);

        match self.mapping {
            ElfMapping::ElfDefault => match mapping_env {
                ELfTargetEnvironment::Host(host_mapper) => host_mapper.map_range(
                    allocator,
                    HostVirtAddr::from_u64(p_vaddr),
                    HostPhysAddr::from_u64(segment.phys_mem[0].start.as_u64()),
                    memsz as usize,
                    flags_to_prot(segment.phdr.p_flags),
                ),
                ELfTargetEnvironment::Guest(guest_mapper) => guest_mapper.map_range(
                    allocator,
                    GuestVirtAddr::from_u64(p_vaddr),
                    GuestPhysAddr::new(segment.phys_mem[0].start.as_usize()),
                    memsz as usize,
                    flags_to_prot(segment.phdr.p_flags),
                ),
            },
            ElfMapping::Identity => match mapping_env {
                ELfTargetEnvironment::Host(host_mapper) => host_mapper.map_range(
                    allocator,
                    HostVirtAddr::from_u64(segment.phys_mem[0].start.as_u64()),
                    HostPhysAddr::from_u64(segment.phys_mem[0].start.as_u64()),
                    memsz as usize,
                    flags_to_prot(segment.phdr.p_flags),
                ),
                ELfTargetEnvironment::Guest(guest_mapper) => guest_mapper.map_range(
                    allocator,
                    GuestVirtAddr::from_u64(segment.phys_mem[0].start.as_u64()),
                    GuestPhysAddr::from_u64(segment.phys_mem[0].start.as_u64()),
                    memsz as usize,
                    flags_to_prot(segment.phdr.p_flags),
                ),
            },
            ElfMapping::Scattered => {
                let p_vaddr = align_page_down(segment.phdr.p_vaddr);

                let mut memsz = segment.phdr.p_memsz;
                if p_vaddr != segment.phdr.p_vaddr {
                    memsz += segment.phdr.p_vaddr - p_vaddr;
                }

                assert!(p_vaddr % PAGE_SIZE as u64 == 0);
                assert!(segment.phys_mem[0].start.as_usize() % PAGE_SIZE == 0);

                match mapping_env {
                    ELfTargetEnvironment::Host(host_mapper) => host_mapper
                        .map_range_scattered(
                            allocator,
                            HostVirtAddr::from_u64(p_vaddr),
                            &segment.phys_mem,
                            memsz as usize,
                            flags_to_prot(segment.phdr.p_flags),
                        )
                        .expect("failed to map segment using Scattered mapping"),
                    ELfTargetEnvironment::Guest(guest_mapper) => guest_mapper
                        .map_range_scattered(
                            allocator,
                            GuestVirtAddr::from_u64(p_vaddr),
                            &segment.phys_mem,
                            memsz as usize,
                            flags_to_prot(segment.phdr.p_flags),
                        )
                        .expect("failed to map segment using Scattered mapping"),
                }
            }
            ElfMapping::ScatteredPaddr => {
                let p_paddr = align_page_down(segment.phdr.p_paddr);

                let mut memsz = segment.phdr.p_memsz;
                if p_paddr != segment.phdr.p_paddr {
                    memsz += segment.phdr.p_paddr - p_paddr;
                }

                assert!(p_paddr % PAGE_SIZE as u64 == 0);
                assert!(segment.phys_mem[0].start.as_usize() % PAGE_SIZE == 0);

                match mapping_env {
                    ELfTargetEnvironment::Host(host_mapper) => host_mapper
                        .map_range_scattered(
                            allocator,
                            HostVirtAddr::from_u64(p_paddr),
                            &segment.phys_mem,
                            memsz as usize,
                            flags_to_prot(segment.phdr.p_flags),
                        )
                        .expect("failed to map segment using Scattered mapping"),
                    ELfTargetEnvironment::Guest(guest_mapper) => guest_mapper
                        .map_range_scattered(
                            allocator,
                            GuestVirtAddr::from_u64(p_paddr),
                            &segment.phys_mem,
                            memsz as usize,
                            flags_to_prot(segment.phdr.p_flags),
                        )
                        .expect("failed to map segment using Scattered mapping"),
                }
            }
        }
    }

    /// Loads an elf segment into memory. Supports both scattered and contiguous physical memory
    unsafe fn load_segment(
        &self,
        segment: &NonContigElf64Phdr,
        host_physical_offset: HostVirtAddr,
    ) {
        // Sanity checks
        assert!(segment.phdr.p_align >= 0x1000);
        assert!(segment.phdr.p_memsz >= segment.phdr.p_filesz);
        assert!(segment.phdr.p_offset + segment.phdr.p_filesz <= self.bytes.len() as u64);
        //Segment might start at an offset. We need to respect the offset when copying the data
        let offset_in_first_page = segment.phdr.p_paddr as usize & PAGE_MASK;

        //Prepare destination
        let mut dest = ScatteredIdMappedBuf::new(
            segment.phys_mem.clone(),
            host_physical_offset.as_usize(),
            offset_in_first_page,
        );
        //Compute offset of data that we wan to copy
        let start = segment.phdr.p_offset as usize;
        let end = (segment.phdr.p_offset + segment.phdr.p_filesz) as usize;
        let source = &self.bytes[start..end];

        //Copy
        dest.write(source)
            .expect("failed to load segment into scattered mem buf");

        // In case the segment is longer than the file size, zero out the rest.
        //(should only be for .bss section)
        if segment.phdr.p_filesz < segment.phdr.p_memsz {
            dest.fill(0x0, (segment.phdr.p_memsz - segment.phdr.p_filesz) as usize)
                .expect("failed to fill zeroed out trailing section");
        }
    }
}

impl LoadedElf {
    /// Load some arbitrary data into memory using the given allocator. The data is loaded contigously in the colored
    /// GPA space but not in the host physical space. We add an identity GVA->GPA mapping to the PTs
    pub fn add_payload(&mut self, data: &[u8], allocator: &impl RangeAllocator) -> GuestVirtAddr {
        let mut ranges = Vec::new();
        let payload_contig_start_gpa = allocator.gpa_of_next_allocation();
        allocator
            .allocate_range(data.len(), |pr: PhysRange| ranges.push(pr))
            .expect("failed to allocate memory for payload");
        //use the identity mapping of the current stage1, to load `data`` to phys addrs in `ranges`
        let mut dest = ScatteredIdMappedBuf::new(ranges.clone(), self.host_physical_offset, 0);
        dest.write(data)
            .expect("failed to write payload's data to memory");

        let payload_gva = GuestVirtAddr::new(payload_contig_start_gpa.as_usize());
        match &mut self.pt_mapper {
            ELfTargetEnvironment::Host(_) => panic!("add_payload called with host mapping"),
            ELfTargetEnvironment::Guest(guest_mapper) => guest_mapper
                .map_range_scattered(allocator, payload_gva, &ranges, data.len(), DEFAULT_PROTS)
                .expect("failed to map payload"),
        };

        payload_gva
    }

    /// Adds a stack to the guest, with an extra guard page.
    ///
    /// Returns the virtual address of the start of the stack (highest address with SysV
    /// conventions, to be put in %rsp) as well as the physical address corresponding to the start
    /// of the stack.
    pub fn add_stack(
        &mut self,
        stack_virt_addr: VirtAddr,
        size: usize,
        guest_allocator: &impl RangeAllocator,
    ) -> (HostVirtAddr, HostPhysAddr) {
        assert!(
            size % PAGE_SIZE == 0,
            "Stack size must be a multiple of page size"
        );
        let mut ranges: Vec<PhysRange> = Vec::new();
        let store_cb = |pr: PhysRange| {
            ranges.push(pr);
        };
        //N.B. we allocate one additional page here for the guard page
        guest_allocator
            .allocate_range(size + PAGE_SIZE, store_cb)
            .expect("Failed to allocate stack");
        // Map guard page
        let guard_virt_addr = HostVirtAddr::new(stack_virt_addr.as_u64() as usize - PAGE_SIZE);
        let guard_phys_addr = HostPhysAddr::new(ranges[0].start.as_usize());
        let stack_guard_prot = PtFlag::PRESENT | PtFlag::EXEC_DISABLE;
        match &mut self.pt_mapper {
            ELfTargetEnvironment::Host(host_mapper) => host_mapper.map_range(
                guest_allocator,
                guard_virt_addr,
                guard_phys_addr,
                PAGE_SIZE,
                stack_guard_prot,
            ),
            ELfTargetEnvironment::Guest(_) => panic!("add stack called for host mapping"),
        };

        // Map stack

        //We allocated the guard page and the remaining stack pages in one go.
        //The "second" physical address is thus the start addr of the actual stack. If the first mem range
        //is only one page, this means we have to use the second mem range entry
        let stack_phys_addr = HostPhysAddr::from_usize(if ranges[0].size() >= 2 * PAGE_SIZE {
            ranges[0].start.as_usize() + PAGE_SIZE
        } else {
            ranges[1].start.as_usize()
        });
        let stack_prot = PtFlag::WRITE | PtFlag::PRESENT | PtFlag::EXEC_DISABLE | PtFlag::USER;
        match &mut self.pt_mapper {
            ELfTargetEnvironment::Host(host_mapper) => host_mapper.map_range(
                guest_allocator,
                HostVirtAddr::new(stack_virt_addr.as_u64() as usize),
                stack_phys_addr,
                size,
                stack_prot,
            ),
            ELfTargetEnvironment::Guest(_) => panic!("add stack called for host mapping"),
        };

        // Start at the top of the stack. Note that the stack must be 16 bytes aligned with SysV
        // conventions.
        let rsp = HostVirtAddr::from_usize(stack_virt_addr.as_u64() as usize + size - 16);
        (rsp, stack_phys_addr)
    }
}

//TODO(aghosn) figure out how to pass a Elf64PhdrFlags argument.
fn flags_to_prot(flags: u32) -> PtFlag {
    let mut prots = PtFlag::empty();
    if flags & Elf64PhdrFlags::PF_R.bits() == Elf64PhdrFlags::PF_R.bits() {
        prots |= PtFlag::PRESENT;
    }
    if flags & Elf64PhdrFlags::PF_W.bits() == Elf64PhdrFlags::PF_W.bits() {
        prots |= PtFlag::WRITE;
    }
    if flags & Elf64PhdrFlags::PF_X.bits() != Elf64PhdrFlags::PF_X.bits() {
        prots |= PtFlag::EXEC_DISABLE;
    }
    prots
}
