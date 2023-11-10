use std::cmp::Ordering;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use mmu::{PtFlag, RVPtFlag};
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};
use object::{elf, Endianness, U16Bytes, U32Bytes, U64Bytes};
use serde::{Deserialize, Serialize};

use crate::allocator::PAGE_SIZE;
use crate::instrument::{CleanupConfig, HashingConfig, MappingPageTables, Security, VitalConfig};
use crate::page_table_mapper::{align_address_up, generate_page_tables};

/// Flags defined by tyche for segments.
#[allow(dead_code)]
#[repr(u32)]
pub enum TychePF {
    #[allow(non_snake_case)]
    PfH = 1 << 3,
    PfC = 1 << 4,
    PfV = 1 << 5,
}

const PT_PHYS_PAGE_MASK: u64 = ((1 << 44) - 1) << RVPtFlag::flags_count(); //TODO(neelu): This is specific for SV48.

// —————————————————————————————— Local Enums ——————————————————————————————— //

#[allow(dead_code)]
#[derive(Debug)]
pub enum ErrorBin {
    SectionMissing = 1,
    SegmentMissing = 2,
    UnalignedAddress = 3,
}

/// OS-specific segment types.
/// Shared/Confidential can be combined with segment.p_flags for RWX.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
#[allow(dead_code)]
#[repr(u32)]
pub enum TychePhdrTypes {
    /// Default value for normal segments.
    NormalLoad = 0x1,
    /// User sandbox (shared) stack.
    UserStackSB = 0x60000001,
    /// User confidential stack.
    UserStackConf = 0x60000002,
    /// User sandbox (shared) segment.
    UserShared = 0x60000003,
    /// User confidential segment.
    UserConfidential = 0x60000004,
    /// Page tables sandbox, always kernel.
    PageTablesSB = 0x60000005,
    /// Page tables confidential, always kernel.
    PageTablesConf = 0x60000006,
    /// Kernel sandbox (shared) stack.
    KernelStackSB = 0x60000007,
    ///  Kernel confidential stack.
    KernelStackConf = 0x60000008,
    /// Kernel sandbox (shared) segment,
    KernelShared = 0x60000009,
    /// Kernel confidential segment.
    KernelConfidential = 0x6000000a,
    /// Kernel pipe segment.
    KernelPipe = 0x6000000b,
    /// Full enclave ELF embedded in application.
    EnclaveELF = object::elf::PT_NOTE,
}

impl TychePhdrTypes {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0x1 => Some(TychePhdrTypes::NormalLoad),
            0x60000001 => Some(TychePhdrTypes::UserStackSB),
            0x60000002 => Some(TychePhdrTypes::UserStackConf),
            0x60000003 => Some(TychePhdrTypes::UserShared),
            0x60000004 => Some(TychePhdrTypes::UserConfidential),
            0x60000005 => Some(TychePhdrTypes::PageTablesSB),
            0x60000006 => Some(TychePhdrTypes::PageTablesConf),
            0x60000007 => Some(TychePhdrTypes::KernelStackSB),
            0x60000008 => Some(TychePhdrTypes::KernelStackConf),
            0x60000009 => Some(TychePhdrTypes::KernelShared),
            0x6000000a => Some(TychePhdrTypes::KernelConfidential),
            0x6000000b => Some(TychePhdrTypes::KernelPipe),
            _ => None,
        }
    }

    pub fn is_user(val: u32) -> bool {
        if let Some(tpe) = Self::from_u32(val) {
            return tpe <= TychePhdrTypes::UserConfidential;
        }
        return false;
    }

    pub fn is_confidential(&self) -> bool {
        match self {
            Self::PageTablesConf => true,
            Self::UserStackConf => true,
            Self::UserConfidential => true,
            Self::KernelStackConf => true,
            Self::KernelConfidential => true,
            _ => false,
        }
    }
}

// ———————————————————————————— Shorthand types ————————————————————————————— //
pub type Shdr64 = elf::SectionHeader64<Endianness>;
pub type Phdr64 = elf::ProgramHeader64<Endianness>;
pub type Ehdr64 = elf::FileHeader64<Endianness>;
pub const DENDIAN: Endianness = Endianness::Little;

// ———————————————————————————— Wrapper Structs ————————————————————————————— //

/// Holds sections for the binary.
/// To ease finding special sections, we make the name directly available.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ModifiedSection {
    pub idx: usize,
    pub name: String,
    pub section_header: Shdr64,
}

/// Holds segments for the binary.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ModifiedSegment {
    pub idx: usize,
    pub program_header: Phdr64,
    pub data: Vec<u8>,
}

/// Maintains the minimal and largest virt addr for the bifnary.
/// This allows to pack new segments tight when we don't care about the addr.
#[derive(Debug)]
pub struct MemoryLayout {
    pub min_addr: u64,
    pub max_addr: u64,
}

/// Holds the ELF we are working on.
/// Has a the binary header, the segments, sections, and raw content.
#[derive(Debug)]
pub struct ModifiedELF {
    pub header: Ehdr64,
    pub segments: Vec<ModifiedSegment>,
    pub sections: Vec<ModifiedSection>,
    pub layout: MemoryLayout,
    pub data: Vec<u8>,
    pub secret_data: Vec<u8>,
}

/// Helper function to convert a T into raw bytes.
/// We use this to more easily parse/write headers.
fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
    }
}

// ————————————————————————————— Implementation ————————————————————————————— //

impl ModifiedELF {
    /// Creates a new boxed ModifiedELF from raw bytes of a binary.
    /// The bytes must include the entire ELF, i.e., headers.
    pub fn new(data: &[u8]) -> Box<ModifiedELF> {
        // Parse the header.
        let hdr = Ehdr64::parse(data).expect("Unable to parse the data");

        let mut melf = Box::new(ModifiedELF {
            header: hdr.clone(),
            segments: Vec::new(),
            sections: Vec::new(),
            layout: MemoryLayout {
                min_addr: u64::MAX,
                max_addr: u64::MIN,
            },
            data: Vec::new(),
            secret_data: Vec::new(),
        });

        // Parse the segments.
        let segs = hdr
            .program_headers(DENDIAN, data)
            .expect("Unable to parse segments");

        for (idx, seg) in segs.iter().enumerate() {
            melf.segments.push(ModifiedSegment {
                idx,
                program_header: seg.clone(),
                data: seg
                    .data(DENDIAN, data)
                    .expect("Unable to get the data")
                    .to_vec(),
            });

            // Find the virtual memory boundaries.
            if ModifiedSegment::is_loadable(seg.p_type(DENDIAN)) {
                let start = seg.p_vaddr(DENDIAN);
                let end = start + seg.p_memsz(DENDIAN);
                if start < melf.layout.min_addr {
                    melf.layout.min_addr = start;
                }
                if end > melf.layout.max_addr {
                    melf.layout.max_addr = align_address_up(end as usize) as u64;
                    assert!(melf.layout.max_addr % 0x1000 == 0);
                }
            }
        }

        // Parse the sections.
        let secs = hdr
            .section_headers(DENDIAN, data)
            .expect("Unable to parse sections");
        let strings = hdr
            .section_strings(DENDIAN, data, secs)
            .expect("Unable to get the strings");

        for (idx, sec) in secs.iter().enumerate() {
            let name = String::from_utf8(
                sec.name(DENDIAN, strings)
                    .expect("Unable to get section name")
                    .to_vec(),
            )
            .expect("Unable to convert the string bytes");

            melf.sections.push(ModifiedSection {
                idx,
                name,
                section_header: sec.clone(),
            });
        }
        // Set the data, compute from what is parsed.
        let data_start: usize = hdr.e_ehsize(DENDIAN) as usize
            + hdr.e_phentsize(DENDIAN) as usize * hdr.e_phnum(DENDIAN) as usize;
        let data_end = hdr.e_shoff(DENDIAN) as usize;

        melf.data = data[data_start..data_end].to_vec();

        log::debug!(
            "Done parsing the binary, virt boundaries are {:x} - {:x}",
            melf.layout.min_addr,
            melf.layout.max_addr
        );
        // Return the elf.
        melf
    }

    /// Check if two ELFs overlap.
    pub fn overlap(&self, other: &ModifiedELF) -> bool {
        let res = self.layout.max_addr >= other.layout.min_addr
            && self.layout.min_addr <= other.layout.max_addr;
        if res {
            log::error!(
                "There is an overlap: [{:x};{:x}] and [{:x}:{:x}]",
                self.layout.min_addr,
                self.layout.max_addr,
                other.layout.min_addr,
                other.layout.max_addr
            );
        }
        res
    }

    /// Change the type of the elf segments.
    pub fn mark(
        &mut self,
        default: TychePhdrTypes,
        cleanup: CleanupConfig,
        vital: VitalConfig,
        hash: HashingConfig,
    ) {
        for seg in &mut self.segments {
            if seg.program_header.p_type(DENDIAN) != object::elf::PT_LOAD {
                continue;
            }
            seg.program_header.p_type = U32Bytes::<Endianness>::new(DENDIAN, default as u32);

            // Mark vital if needed.
            if vital == VitalConfig::AllVital {
                let mut flags = seg.program_header.p_flags(DENDIAN);
                flags |= TychePF::PfV as u32;
                seg.program_header.p_flags = U32Bytes::<Endianness>::new(DENDIAN, flags as u32);
            }
            // Chose the cleanup strategy.
            match cleanup {
                CleanupConfig::AllCleanup => {
                    let mut flags = seg.program_header.p_flags(DENDIAN);
                    flags |= TychePF::PfC as u32;
                    seg.program_header.p_flags = U32Bytes::<Endianness>::new(DENDIAN, flags as u32);
                }
                CleanupConfig::WritableCleanup => {
                    if (seg.program_header.p_flags(DENDIAN) & object::elf::PF_W)
                        == object::elf::PF_W
                    {
                        let mut flags = seg.program_header.p_flags(DENDIAN);
                        flags |= TychePF::PfC as u32;
                        seg.program_header.p_flags =
                            U32Bytes::<Endianness>::new(DENDIAN, flags as u32);
                    }
                }
                _ => {}
            }
            // Chose the hashing strategy.
            match hash {
                HashingConfig::NoHash => {}
                HashingConfig::AllHash => {
                    let mut flags = seg.program_header.p_flags(DENDIAN);
                    flags |= TychePF::PfH as u32;
                    seg.program_header.p_flags = U32Bytes::<Endianness>::new(DENDIAN, flags as u32);
                }
                HashingConfig::ContentHash => {
                    if seg.program_header.p_filesz(DENDIAN) != 0 {
                        let mut flags = seg.program_header.p_flags(DENDIAN);
                        flags |= TychePF::PfH as u32;
                        seg.program_header.p_flags =
                            U32Bytes::<Endianness>::new(DENDIAN, flags as u32);
                    }
                }
            }
        }
    }

    /// Merge the other modified ELF into this one.
    pub fn merge(&mut self, other: &ModifiedELF) {
        //TODO merge the two binaries together.
        //It's gonna be funky to merge sections if we want them to appear
        //And to merge the strtab from both ..
        //For the moment, just add the segments.
        for seg in &other.segments {
            self.append_other_segment(seg);
        }
        // Replace the entry point of the current.
        let y = self.header.e_entry(DENDIAN);
        log::debug!("Entry of user binary {:#x}", y);
        let x = other.header.e_entry(DENDIAN);
        log::debug!("Entry of the kernel binary {:#x}", x);
        self.header.e_entry = other.header.e_entry;
    }

    /// Generate the page tables for this ELF and add them into their own segment.
    pub fn generate_page_tables(
        &mut self,
        security: Security,
        flags: u32,
        map_page_tables: &Option<MappingPageTables>,
        riscv_enabled: bool,
        vf2_enabled: bool,
    ) {
        let (pts, nb_pages, cr3) =
            generate_page_tables(self, map_page_tables, riscv_enabled, vf2_enabled);
        let tpe = if security == Security::Confidential {
            TychePhdrTypes::PageTablesConf
        } else {
            TychePhdrTypes::PageTablesSB
        };
        self.append_data_segment(
            Some(cr3 as u64),
            tpe as u32,
            flags,
            //NEELU: object::elf::PF_R | object::elf::PF_W | object::elf::PF_X,
            nb_pages * PAGE_SIZE,
            &pts,
        );
    }

    /// Returns all segments of a given type.
    pub fn find_segments(&self, segtype: TychePhdrTypes) -> Vec<&ModifiedSegment> {
        let mut res = Vec::new();
        for seg in &self.segments {
            if let Some(tpe) = TychePhdrTypes::from_u32(seg.program_header.p_type(DENDIAN)) {
                if tpe == segtype {
                    res.push(seg);
                }
            }
        }
        return res;
    }

    /// Adds offset to all non-empty entries in the page table.
    /// This is used by the loader at run time.
    pub fn fix_page_tables(&mut self, offset: u64, riscv_enabled: bool) {
        let mut page_seg: Option<&mut ModifiedSegment> = None;
        {
            for seg in &mut self.segments {
                if let Some(tpe) = TychePhdrTypes::from_u32(seg.program_header.p_type(DENDIAN)) {
                    if tpe == TychePhdrTypes::PageTablesConf || tpe == TychePhdrTypes::PageTablesSB
                    {
                        page_seg = Some(seg);
                        break;
                    }
                }
            }
            if page_seg.is_none() {
                panic!("Unable to find the page tables for this ELF!");
            }
        };

        let tables: &mut [u64] = unsafe {
            let slice_bytes: &[u8] = page_seg.unwrap().data.as_mut_slice();
            std::slice::from_raw_parts_mut(slice_bytes.as_ptr() as *mut u64, slice_bytes.len() / 8)
        };

        let page_offset_width: u64 = 12; //TODO(neelu): Generalize this, it assumes 4 KB pages.
        let page_offset_mask: u64 = 0x1000 - 1;
        if (offset & !page_offset_mask) != offset {
            panic!("The offset is not page aligned.");
        }

        if !riscv_enabled {
            // TODO(aghosn) I am lazy, is it correct to do a simple add?
            for entry in tables.iter_mut() {
                if *entry != 0 && (*entry & PtFlag::PRESENT.bits() == PtFlag::PRESENT.bits()) {
                    *entry += offset;
                }
            }
        } else {
            for entry in tables.iter_mut() {
                if *entry != 0 && (*entry & RVPtFlag::VALID.bits() == RVPtFlag::VALID.bits()) {
                    let ppn = (offset >> page_offset_width) + (*entry >> RVPtFlag::flags_count());
                    *entry = (*entry & !PT_PHYS_PAGE_MASK) | (ppn << RVPtFlag::flags_count());
                    log::debug!("Fixing page tables: entry: {:x} and ppn: {:x}", *entry, ppn);
                }
            }
        }
    }

    /// Dumps the content of the ELF into a file.
    pub fn dump_to_file(&mut self, output: &PathBuf, sort: bool) {
        let content = self.dump(sort);
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(output)
            .expect("Unable to open output file.");
        file.write(&*content).expect("Unable to dump the content");
        log::debug!("Done writing the binary");
    }
    /// Writes a ModifiedELF into a vector of bytes and returns it.
    pub fn dump(&mut self, sort: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(self.len());
        let mut writer = object::write::elf::Writer::new(DENDIAN, true, &mut out);

        // Do some cleaning, sort segments by vaddr.
        if sort {
            self.segments.sort_by(|a, b| {
                let a_addr = a.program_header.p_vaddr(DENDIAN);
                let b_addr = b.program_header.p_vaddr(DENDIAN);
                if a.program_header.p_type(DENDIAN) == TychePhdrTypes::PageTablesConf as u32 {
                    Ordering::Greater
                } else if b.program_header.p_type(DENDIAN) == TychePhdrTypes::PageTablesConf as u32
                {
                    Ordering::Less
                } else if a.program_header.p_type(DENDIAN) == TychePhdrTypes::PageTablesSB as u32 {
                    Ordering::Greater
                } else if b.program_header.p_type(DENDIAN) == TychePhdrTypes::PageTablesSB as u32 {
                    Ordering::Less
                } else {
                    a_addr.cmp(&b_addr)
                }
            });
        }

        //Write the header.
        let hdr_bytes = any_as_u8_slice(&self.header);
        writer.write(hdr_bytes);

        // Write the program headers.
        for seg in &self.segments {
            let seg_bytes = any_as_u8_slice(&seg.program_header);
            writer.write(seg_bytes);
        }
        // Write program content.
        writer.write(&self.data);
        // Sections.
        for sec in &self.sections {
            let sec_bytes = any_as_u8_slice(&sec.section_header);
            writer.write(sec_bytes);
        }
        // Write secret data too.
        writer.write(&self.secret_data);
        out
    }

    /// Returns the length of an ELF header.
    pub fn len_hdr(&self) -> usize {
        std::mem::size_of::<Ehdr64>()
    }

    /// Returns the length of of all the binary's program headers (segments).
    pub fn len_phdrs(&self) -> usize {
        ModifiedSegment::len() * self.segments.len()
    }

    /// Returns start address of the elf
    pub fn elf_start(&self) -> u64 {
        self.header.e_entry(DENDIAN)
    }

    /// Computes and returns the length of the ELF binary.
    pub fn len(&mut self) -> usize {
        let header = self.len_hdr();
        let prog_headers: usize = self.len_phdrs();
        let data = self.data.len();
        let secs: usize = ModifiedSection::len() * self.sections.len();
        let secret: usize = self.secret_data.len();
        return header + prog_headers + data + secs + secret;
    }

    /// Helper to construct a new program header (segment).
    fn construct_phdr(
        seg_type: u32,
        flags: u32,
        offset: u64,
        filesz: u64,
        vaddr: u64,
        memsz: u64,
        align: u64,
    ) -> Phdr64 {
        Phdr64 {
            p_type: U32Bytes::new(DENDIAN, seg_type),
            p_flags: U32Bytes::new(DENDIAN, flags),
            p_offset: U64Bytes::new(DENDIAN, offset),
            p_vaddr: U64Bytes::new(DENDIAN, vaddr),
            p_paddr: U64Bytes::new(DENDIAN, 0),
            p_filesz: U64Bytes::new(DENDIAN, filesz),
            p_memsz: U64Bytes::new(DENDIAN, memsz),
            p_align: U64Bytes::new(DENDIAN, align),
        }
    }

    /// Helper to construct a new section header.
    pub fn construct_shdr(
        name: u32,
        sec_type: u32,
        flags: u64,
        offset: u64,
        filesz: u64,
        vaddr: u64,
        memsz: u64,
        align: u64,
    ) -> Shdr64 {
        Shdr64 {
            sh_name: U32Bytes::new(DENDIAN, name),
            sh_type: U32Bytes::new(DENDIAN, sec_type),
            sh_flags: U64Bytes::new(DENDIAN, flags),
            sh_addr: U64Bytes::new(DENDIAN, vaddr),
            sh_offset: U64Bytes::new(DENDIAN, offset),
            sh_size: U64Bytes::new(DENDIAN, memsz),
            sh_info: U32Bytes::new(DENDIAN, 0),
            sh_addralign: U64Bytes::new(DENDIAN, align),
            sh_entsize: U64Bytes::new(DENDIAN, filesz),
            sh_link: U32Bytes::new(DENDIAN, 0),
        }
    }

    /// Creates and inserts a new segment without file data.
    /// If no vaddr is provided, the segment is added a the max vaddr so far
    /// in the binary.
    #[allow(dead_code)]
    pub fn append_nodata_segment(
        &mut self,
        vaddr: Option<u64>,
        seg_type: u32,
        flags: u32,
        size: usize,
    ) {
        let addr = vaddr.unwrap_or(self.layout.max_addr);
        // Update the max address.
        if addr + size as u64 > self.layout.max_addr {
            self.layout.max_addr = addr + size as u64;
            assert!(self.layout.max_addr % 0x1000 == 0);
        }

        //Create header.
        let phdr = Self::construct_phdr(seg_type, flags, 0, 0, addr, size as u64, PAGE_SIZE as u64);

        // Simply add it to the segments.
        self.add_segment_header(&phdr, None);
    }

    pub fn append_other_segment(&mut self, other: &ModifiedSegment) {
        self.append_data_segment(
            Some(other.program_header.p_vaddr(DENDIAN)),
            other.program_header.p_type(DENDIAN),
            other.program_header.p_flags(DENDIAN),
            other.program_header.p_memsz(DENDIAN) as usize,
            &other.data,
        );
    }

    /// Appends a data segment to the binary.
    /// If no vaddr is provided, the segment is added at the max vaddr so far
    /// in the binary.
    #[allow(dead_code)]
    pub fn append_data_segment(
        &mut self,
        vaddr: Option<u64>,
        seg_type: u32,
        flags: u32,
        size: usize,
        data: &Vec<u8>,
    ) {
        // offset need to take into account the headers as well.
        let foff: u64 = (self.data.len() + self.len_hdr() + self.len_phdrs()) as u64;
        let fsize: u64 = data.len() as u64;
        self.data.extend(data);

        let addr = vaddr.unwrap_or(self.layout.max_addr);

        // Update the max address.
        if addr + size as u64 > self.layout.max_addr {
            self.layout.max_addr = align_address_up(addr as usize + size) as u64;
            assert!(self.layout.max_addr % 0x1000 == 0);
        }

        // Fix the header.
        let shoff = self.header.e_shoff(DENDIAN) + fsize;
        self.header.e_shoff = U64Bytes::new(DENDIAN, shoff);

        // Create a header.
        let phdr = Self::construct_phdr(
            seg_type,
            flags,
            foff,
            fsize,
            addr,
            size as u64,
            PAGE_SIZE as u64,
        );

        self.add_segment_header(&phdr, Some(data));
    }

    pub fn add_section_header(&mut self, shdr: &Shdr64) {
        self.sections.push(ModifiedSection {
            idx: self.sections.len(),
            name: "Special".to_string(),
            section_header: *shdr,
        });
        self.header.e_shnum.set(DENDIAN, self.sections.len() as u16);
    }

    /// Adds a segment header to the binary and patches offsets.
    pub fn add_segment_header(&mut self, phdr: &Phdr64, data: Option<&Vec<u8>>) {
        let delta = ModifiedSegment::len() as u64;
        let affected = (self.len_hdr() + self.len_phdrs()) as u64;
        self.segments.push(ModifiedSegment {
            idx: self.segments.len(),
            program_header: phdr.clone(),
            data: data.unwrap_or(&Vec::new()).clone(),
        });

        for seg in &mut self.segments {
            seg.patch_offset(delta, affected);
        }
        for sec in &mut self.sections {
            sec.patch_offset(delta, affected);
        }
        // Patch the header.
        self.header.e_phnum = U16Bytes::new(DENDIAN, self.segments.len() as u16);
        let shoff = self.header.e_shoff(DENDIAN);
        self.header.e_shoff = U64Bytes::new(DENDIAN, shoff + delta);

        // All done!
    }

    /// Relocates a section into its own segment.
    /// The section needs to be aligned (start and end).
    #[allow(dead_code)]
    pub fn split_segment_at_section(
        &mut self,
        sec_name: &str,
        seg_type: u32,
        data: &Vec<u8>,
    ) -> Result<(), ErrorBin> {
        // Find the section with the right name.
        let (sec_start, sec_end, sec_fstart, sec_fend) = {
            let sec_to_move = match self.sections.iter().find(|s| s.name == sec_name) {
                Some(s) => s,
                None => {
                    return Err(ErrorBin::SectionMissing);
                }
            };

            // Get virtual boundaries.
            let (sec_start, sec_end) = sec_to_move.get_vaddr_bounds();
            if sec_start % PAGE_SIZE as u64 != 0 || sec_end % PAGE_SIZE as u64 != 0 {
                log::error!(
                    "Section {} has unaligned start {:x} or end {:x}",
                    sec_to_move.name,
                    sec_start,
                    sec_end
                );
                return Err(ErrorBin::UnalignedAddress);
            }
            let (sec_fstart, sec_fend) = sec_to_move.get_file_bounds();
            (sec_start, sec_end, sec_fstart, sec_fend)
        };

        // Find the segment that contains it.
        let (seg_start, seg_end, seg_fstart, seg_fend, seg_template, seg_data) = {
            let seg: &mut ModifiedSegment = match self.segments.iter_mut().find(|s| {
                let (start, end) = s.get_vaddr_bounds();
                start <= sec_start && end >= sec_end
            }) {
                Some(s) => s,
                None => {
                    return Err(ErrorBin::SegmentMissing);
                }
            };
            let (seg_start, seg_end) = seg.get_vaddr_bounds();
            let (seg_fstart, seg_fend) = seg.get_file_bounds();
            let copy = seg.program_header.clone();
            // middle, change in place.
            seg.program_header.p_type = U32Bytes::new(DENDIAN, seg_type);
            seg.program_header.p_offset = U64Bytes::new(DENDIAN, sec_fstart);
            seg.program_header.p_filesz = U64Bytes::new(DENDIAN, sec_fend - sec_fstart);
            // Fix addresses.
            seg.program_header.p_vaddr = U64Bytes::new(DENDIAN, sec_start);
            seg.program_header.p_memsz = U64Bytes::new(DENDIAN, sec_end - sec_start);
            // Data for the segment.
            let sidx = seg.program_header.p_offset(DENDIAN) as usize;
            let eidx = sidx + seg.program_header.p_filesz(DENDIAN) as usize;
            let seg_data = &data[sidx..eidx];

            (
                seg_start,
                seg_end,
                seg_fstart,
                seg_fend,
                copy,
                seg_data.to_vec(),
            )
        };

        // Figure out the split.
        // Left side.
        if seg_start < sec_start {
            let mut phdr = seg_template.clone();
            // Fix the file size.
            let left_fsize = u64::min(sec_start - seg_start, seg_fend - seg_fstart);
            phdr.p_filesz = U64Bytes::new(DENDIAN, left_fsize);
            // Patch addresses
            phdr.p_vaddr = U64Bytes::new(DENDIAN, seg_start);
            phdr.p_memsz = U64Bytes::new(DENDIAN, sec_start - seg_start);
            // Add the header, don't worry about sorting for now.
            self.add_segment_header(&phdr, Some(&seg_data));
        }

        // right.
        if sec_end < seg_end {
            let mut phdr = seg_template.clone();
            // Fix the fileoff
            let right_off = sec_fend;
            phdr.p_offset = U64Bytes::new(DENDIAN, right_off);
            phdr.p_filesz = U64Bytes::new(DENDIAN, seg_fend - right_off);
            // Patch addresses
            phdr.p_vaddr = U64Bytes::new(DENDIAN, sec_end);
            phdr.p_memsz = U64Bytes::new(DENDIAN, seg_end - sec_end);
            // Add the header, don't worry about sorting for now.
            self.add_segment_header(&phdr, Some(&seg_data));
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn set_attestation_hash(&mut self) {
        for seg in &mut self.segments {
            if ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
                if let Some(_tpe) = TychePhdrTypes::from_u32(seg.program_header.p_type(DENDIAN)) {
                    if seg.should_include_attestation() {
                        seg.set_mask_flags(TychePF::PfH as u32);
                    }
                }
            }
        }
    }
}

impl ModifiedSegment {
    /// Patches the offset inside a segment with delta if the offset
    /// is greater than the affected address.
    pub fn patch_offset(&mut self, delta: u64, _affected: u64) {
        let offset = self.program_header.p_offset(DENDIAN);
        if self.program_header.p_filesz(DENDIAN) > 0 {
            self.program_header.p_offset = U64Bytes::new(DENDIAN, offset + delta);
        }
    }

    /// Returns vaddr - vend for the segment.
    #[allow(dead_code)]
    pub fn get_vaddr_bounds(&self) -> (u64, u64) {
        let start = self.program_header.p_vaddr(DENDIAN);
        let end = start + self.program_header.p_memsz(DENDIAN);
        (start, end)
    }

    /// Returns foffset - foffset + fsize.
    #[allow(dead_code)]
    pub fn get_file_bounds(&self) -> (u64, u64) {
        let fstart = self.program_header.p_offset(DENDIAN);
        let fsize = self.program_header.p_filesz(DENDIAN);
        (fstart, fstart + fsize)
    }

    /// Returns the length of a program header (segment).
    pub fn len() -> usize {
        std::mem::size_of::<Phdr64>()
    }

    /// Determines if the segment must be loaded.
    pub fn is_loadable(value: u32) -> bool {
        match value {
            elf::PT_LOAD => true,
            val => match TychePhdrTypes::from_u32(val) {
                Some(tpe) => tpe != TychePhdrTypes::EnclaveELF,
                None => false,
            },
        }
    }

    pub fn should_include_attestation(&mut self) -> bool {
        if let Some(tpe) = TychePhdrTypes::from_u32(self.program_header.p_type(DENDIAN)) {
            tpe.is_confidential()
        } else {
            false
        }
    }

    #[allow(dead_code)]
    pub fn set_mask_flags(&mut self, mask: u32) {
        let fl = self.program_header.p_flags(DENDIAN);
        self.program_header.p_flags = U32Bytes::new(DENDIAN, fl | mask);
    }
}

impl ModifiedSection {
    /// Patches the offset inside a section with delta if the offset
    /// is greater than the affected address.
    #[allow(dead_code)]
    pub fn patch_offset(&mut self, delta: u64, affected: u64) {
        let offset = self.section_header.sh_offset(DENDIAN);
        if offset >= affected {
            self.section_header.sh_offset = U64Bytes::new(DENDIAN, offset + delta);
        }
    }

    /// Returns vaddr - vend for the section.
    #[allow(dead_code)]
    pub fn get_vaddr_bounds(&self) -> (u64, u64) {
        let start = self.section_header.sh_addr(DENDIAN);
        let end = start + self.section_header.sh_size(DENDIAN);
        (start, end)
    }

    /// Returns foffset - foffset + fsize.
    #[allow(dead_code)]
    pub fn get_file_bounds(&self) -> (u64, u64) {
        if self.section_header.sh_type(DENDIAN) == elf::SHT_NOBITS {
            return (0, 0);
        }
        let fstart = self.section_header.sh_offset(DENDIAN);
        let fsize = self.section_header.sh_size(DENDIAN);
        (fstart, fstart + fsize)
    }

    /// Returns the length of a section header.
    pub fn len() -> usize {
        std::mem::size_of::<Shdr64>()
    }
}
