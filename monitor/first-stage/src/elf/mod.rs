//! Executable and Linkable Format - ELF

mod ffi;

use alloc::vec::Vec;
use core::str::from_utf8;

pub use ffi::{
    Elf64Hdr, Elf64Phdr, Elf64PhdrFlags, Elf64PhdrType, Elf64Shdr, Elf64ShdrType, Elf64Sym,
    FromBytes,
};
use mmu::walker::Address;
use mmu::{PtFlag, PtMapper, RangeAllocator};

use crate::{GuestPhysAddr, GuestVirtAddr, HostVirtAddr};

const PAGE_SIZE: usize = 0x1000;

pub enum ElfMapping {
    /// Respect the virtual-to-physical mapping of the ELF file.
    ElfDefault,
    /// Use an identity mapping, i.e. virtual addresses becomes equal to physical addresses.
    Identity,
}

/// An ELF program that can be loaded as a guest.
pub struct ElfProgram {
    /// The entry point, as a guest virtual address.
    pub entry: GuestVirtAddr,
    /// The entry point, as a guest physical address.
    ///
    /// To be used with identity mapping.
    pub phys_entry: GuestPhysAddr,
    pub segments: Vec<Elf64Phdr>,
    pub sections: Vec<Elf64Shdr>,
    pub bytes: &'static [u8],
    mapping: ElfMapping,
}

pub struct LoadedElf<PhysAddr, VirtAddr> {
    /// The root of initial page tables.
    pub pt_root: PhysAddr,
    /// Offset in the host, used to load the guest into memory.
    host_physical_offset: HostVirtAddr,
    /// The page table mapper of the guest.
    pub pt_mapper: PtMapper<PhysAddr, VirtAddr>,
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
            segments: prog_headers,
            sections,
            mapping: ElfMapping::ElfDefault,
            bytes,
        }
    }

    /// Configures the mappings for this program.
    pub fn set_mapping(&mut self, mapping: ElfMapping) {
        self.mapping = mapping;
    }

    /// Loads the guest program and setup the page table inside the guest memory.
    ///
    /// On success, returns the guest physical address of the guest page table root (to bet set as
    /// CR3).
    pub fn load<PhysAddr, VirtAddr>(
        &self,
        guest_allocator: &impl RangeAllocator,
        host_physical_offset: HostVirtAddr,
    ) -> Result<LoadedElf<PhysAddr, VirtAddr>, ()>
    where
        PhysAddr: Address,
        VirtAddr: Address,
    {
        // Compute the highest physical address used by the guest.
        // The remaining space can be used to allocate page tables.
        let mut highest_addr = 0;
        for seg in self.segments.iter() {
            if seg.p_type != Elf64PhdrType::PT_LOAD.bits() {
                continue;
            }
            highest_addr = core::cmp::max(highest_addr, seg.p_paddr + seg.p_memsz);
        }

        let pt_root = guest_allocator.allocate_frame().ok_or(())?.zeroed();
        let pt_root_guest_phys_addr = PhysAddr::from_usize(pt_root.phys_addr.as_usize());
        let mut pt_mapper =
            PtMapper::new(host_physical_offset.as_usize(), 0, pt_root_guest_phys_addr);

        // Load and map segments
        for seg in self.segments.iter() {
            if seg.p_type != Elf64PhdrType::PT_LOAD.bits() {
                // Skip non-load segments.
                continue;
            }
            unsafe {
                // TODO: ensure that the segment does not overlap host memory
                self.load_segment(seg, host_physical_offset);
                self.map_segment(seg, &mut pt_mapper, guest_allocator);
            }
        }

        Ok(LoadedElf {
            pt_root: pt_root_guest_phys_addr,
            host_physical_offset,
            pt_mapper,
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
    unsafe fn map_segment<PhysAddr, VirtAddr>(
        &self,
        segment: &Elf64Phdr,
        mapper: &mut PtMapper<PhysAddr, VirtAddr>,
        guest_allocator: &impl RangeAllocator,
    ) where
        PhysAddr: Address,
        VirtAddr: Address,
    {
        let align_page_down = |addr: u64| addr & !(PAGE_SIZE as u64 - 1);
        let p_vaddr = align_page_down(segment.p_vaddr);
        let p_paddr = align_page_down(segment.p_paddr);

        let mut memsz = segment.p_memsz;
        if p_vaddr != segment.p_vaddr {
            memsz += segment.p_vaddr - p_vaddr;
        }

        assert!(p_vaddr % PAGE_SIZE as u64 == 0);
        assert!(p_paddr % PAGE_SIZE as u64 == 0);

        match self.mapping {
            ElfMapping::ElfDefault => {
                mapper.map_range(
                    guest_allocator,
                    VirtAddr::from_u64(p_vaddr),
                    PhysAddr::from_u64(p_paddr),
                    memsz as usize,
                    flags_to_prot(segment.p_flags),
                );
            }
            ElfMapping::Identity => {
                mapper.map_range(
                    guest_allocator,
                    VirtAddr::from_u64(p_paddr),
                    PhysAddr::from_u64(p_paddr),
                    memsz as usize,
                    flags_to_prot(segment.p_flags),
                );
            }
        }
    }

    /// Loads an elf segment at the desired physical address.
    unsafe fn load_segment(&self, segment: &Elf64Phdr, host_physical_offset: HostVirtAddr) {
        // Sanity checks
        assert!(segment.p_align >= 0x1000);
        assert!(segment.p_memsz >= segment.p_filesz);
        assert!(segment.p_offset + segment.p_filesz <= self.bytes.len() as u64);

        // Prepare destination
        log::debug!(
            "Loading segment [0x{:x}, 0x{:x}]",
            segment.p_paddr,
            segment.p_paddr + segment.p_memsz
        );
        let dest = core::slice::from_raw_parts_mut(
            (segment.p_paddr + host_physical_offset.as_u64()) as *mut u8,
            segment.p_filesz as usize,
        );

        let start = segment.p_offset as usize;
        let end = (segment.p_offset + segment.p_filesz) as usize;
        let source = &self.bytes[start..end];
        dest.copy_from_slice(source);

        // In case the segment is longer than the file size, zero out the rest.
        if segment.p_filesz < segment.p_memsz {
            let zeroed = core::slice::from_raw_parts_mut(
                (segment.p_paddr + segment.p_filesz + host_physical_offset.as_u64()) as *mut u8,
                (segment.p_memsz - segment.p_filesz) as usize,
            );
            zeroed.fill(0);
        }
    }
}

impl<PhysAddr, VirtAddr> LoadedElf<PhysAddr, VirtAddr>
where
    PhysAddr: Address,
    VirtAddr: Address,
{
    /// Adds a paylog to a free location of the guest memory and returns the chosen location.
    pub fn add_payload(
        &mut self,
        data: &[u8],
        guest_allocator: &impl RangeAllocator,
    ) -> GuestPhysAddr {
        let range = guest_allocator
            .allocate_range(data.len())
            .expect("Failed to allocate guest payload");
        let host_virt_addr =
            (range.start.as_usize() + self.host_physical_offset.as_usize()) as *mut u8;
        unsafe {
            let dest = core::slice::from_raw_parts_mut(host_virt_addr, data.len());
            dest.copy_from_slice(data);
        }
        GuestPhysAddr::new(range.start.as_usize())
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
    ) -> (VirtAddr, PhysAddr) {
        assert!(
            size % PAGE_SIZE == 0,
            "Stack size must be a multiple of page size"
        );
        let range = guest_allocator
            .allocate_range(size + PAGE_SIZE)
            .expect("Failed to allocate stack");

        // Map guard page
        let guard_virt_addr = VirtAddr::from_usize(stack_virt_addr.as_usize() - PAGE_SIZE);
        let guard_phys_addr = PhysAddr::from_usize(range.start.as_usize());
        let stack_guard_prot = PtFlag::PRESENT | PtFlag::EXEC_DISABLE;
        self.pt_mapper.map_range(
            guest_allocator,
            guard_virt_addr,
            guard_phys_addr,
            PAGE_SIZE,
            stack_guard_prot,
        );

        // Map stack
        let stack_phys_addr = PhysAddr::from_usize(range.start.as_usize() + PAGE_SIZE);
        let stack_prot = PtFlag::WRITE | PtFlag::PRESENT | PtFlag::EXEC_DISABLE | PtFlag::USER;
        self.pt_mapper.map_range(
            guest_allocator,
            stack_virt_addr,
            stack_phys_addr,
            size,
            stack_prot,
        );

        // Start at the top of the stack. Note that the stack must be 16 bytes aligned with SysV
        // conventions.
        let rsp = VirtAddr::from_usize(stack_virt_addr.as_usize() + size - 16);
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
