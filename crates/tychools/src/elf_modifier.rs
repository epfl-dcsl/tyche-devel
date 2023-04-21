use object::elf::PT_LOAD;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};
use object::{elf, Endianness, U16Bytes, U32Bytes, U64Bytes};

use crate::allocator::PAGE_SIZE;

#[allow(dead_code)]
#[derive(Debug)]
pub enum ErrorBin {
    SectionMissing = 1,
    SegmentMissing = 2,
    UnalignedAddress = 3,
}

#[derive(Debug)]
#[allow(dead_code)]
#[repr(u32)]
pub enum TychePhdrTypes {
    PageTables = 0x60000000,
    EnclStack = 0x60000001,
    Shared = 0x60000002,
    Condidential = 0x60000003,
}

// ———————————————————————————— Shorthand types ————————————————————————————— //
pub type Shdr64 = elf::SectionHeader64<Endianness>;
pub type Phdr64 = elf::ProgramHeader64<Endianness>;
pub type Ehdr64 = elf::FileHeader64<Endianness>;
pub const DENDIAN: Endianness = Endianness::Little;

// ———————————————————————————— Wrapper Structs ————————————————————————————— //
#[allow(dead_code)]
#[derive(Debug)]
pub struct ModifiedSection {
    pub idx: usize,
    pub name: String,
    pub section_header: Shdr64,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ModifiedSegment {
    pub idx: usize,
    pub program_header: Phdr64,
}

#[derive(Debug)]
pub struct MemoryLayout {
    pub min_addr: u64,
    pub max_addr: u64,
}

#[derive(Debug)]
pub struct ModifiedELF {
    pub header: Ehdr64,
    pub segments: Vec<ModifiedSegment>,
    pub sections: Vec<ModifiedSection>,
    pub layout: MemoryLayout,
    pub data: Vec<u8>,
}

fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
    }
}

impl ModifiedELF {
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
        });

        // Parse the segments.
        let segs = hdr
            .program_headers(DENDIAN, data)
            .expect("Unable to parse segments");

        for (idx, seg) in segs.iter().enumerate() {
            melf.segments.push(ModifiedSegment {
                idx,
                program_header: seg.clone(),
            });

            // Find the virtual memory boundaries.
            if seg.p_type(DENDIAN) == PT_LOAD {
                let start = seg.p_vaddr(DENDIAN);
                let end = start + seg.p_memsz(DENDIAN);
                if start < melf.layout.min_addr {
                    melf.layout.min_addr = start;
                }
                if end > melf.layout.max_addr {
                    melf.layout.max_addr = end;
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
                idx: idx,
                name: name,
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

    /// Dump this object into the provided vector.
    pub fn dump(&mut self, out: &mut object::write::elf::Writer) {
        log::info!("The computed size is {}", self.len());

        // Do some cleaning, sort segments by vaddr.
        self.segments.sort_by(|a, b| {
            let a_addr = a.program_header.p_vaddr(DENDIAN);
            let b_addr = b.program_header.p_vaddr(DENDIAN);
            a_addr.cmp(&b_addr)
        });

        //Write the header.
        let hdr_bytes = any_as_u8_slice(&self.header);
        out.write(hdr_bytes);
        // Write the program headers.
        for seg in &self.segments {
            let seg_bytes = any_as_u8_slice(&seg.program_header);
            out.write(seg_bytes);
        }
        // Write program content.
        out.write(&self.data);
        // Sections.
        for sec in &self.sections {
            let sec_bytes = any_as_u8_slice(&sec.section_header);
            out.write(sec_bytes);
        }
        log::debug!("Done writting the binary");
    }

    pub fn len_hdr(&self) -> usize {
        std::mem::size_of::<Ehdr64>()
    }

    pub fn len_phdrs(&self) -> usize {
        ModifiedSegment::len() * self.segments.len()
    }

    /// Compute the length required in bytes.
    pub fn len(&mut self) -> usize {
        let header = self.len_hdr();
        let prog_headers: usize = self.len_phdrs();
        let data = self.data.len();
        let secs: usize = ModifiedSection::len() * self.sections.len();
        return header + prog_headers + data + secs;
    }

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

    #[allow(dead_code)]
    fn construct_shdr(
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
        }

        //Create header.
        let phdr = Self::construct_phdr(seg_type, flags, 0, 0, addr, size as u64, PAGE_SIZE as u64);

        // Simply add it to the segments.
        self.add_segment_header(&phdr);
    }

    #[allow(dead_code)]
    pub fn append_data_segment(
        &mut self,
        vaddr: Option<u64>,
        seg_type: u32,
        flags: u32,
        size: usize,
        data: &Vec<u8>,
    ) {
        let foff: u64 = self.data.len() as u64;
        let fsize: u64 = data.len() as u64;
        self.data.extend(data);

        let addr = vaddr.unwrap_or(self.layout.max_addr);

        // Update the max address.
        if addr + size as u64 > self.layout.max_addr {
            self.layout.max_addr = addr + size as u64;
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

        self.add_segment_header(&phdr);
    }

    pub fn add_segment_header(&mut self, phdr: &Phdr64) {
        let delta = ModifiedSegment::len() as u64;
        let affected = (self.len_hdr() + self.len_phdrs()) as u64;
        self.segments.push(ModifiedSegment {
            idx: self.segments.len(),
            program_header: phdr.clone(),
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

    /// This function relocates a section into its own segment.
    #[allow(dead_code)]
    pub fn split_segment_at_section(
        &mut self,
        sec_name: &str,
        seg_type: u32,
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
        let (seg_start, seg_end, seg_fstart, seg_fend, seg_template) = {
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

            (seg_start, seg_end, seg_fstart, seg_fend, copy)
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
            self.add_segment_header(&phdr);
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
            self.add_segment_header(&phdr);
        }

        Ok(())
    }
}

impl ModifiedSegment {
    pub fn patch_offset(&mut self, delta: u64, affected: u64) {
        let offset = self.program_header.p_offset(DENDIAN);
        if offset >= affected {
            self.program_header.p_offset = U64Bytes::new(DENDIAN, offset + delta);
        }
    }

    #[allow(dead_code)]
    pub fn get_vaddr_bounds(&self) -> (u64, u64) {
        let start = self.program_header.p_vaddr(DENDIAN);
        let end = start + self.program_header.p_memsz(DENDIAN);
        (start, end)
    }

    #[allow(dead_code)]
    pub fn get_file_bounds(&self) -> (u64, u64) {
        let fstart = self.program_header.p_offset(DENDIAN);
        let fsize = self.program_header.p_filesz(DENDIAN);
        (fstart, fstart + fsize)
    }

    pub fn len() -> usize {
        std::mem::size_of::<Phdr64>()
    }
}

impl ModifiedSection {
    #[allow(dead_code)]
    pub fn patch_offset(&mut self, delta: u64, affected: u64) {
        let offset = self.section_header.sh_offset(DENDIAN);
        if offset >= affected {
            self.section_header.sh_offset = U64Bytes::new(DENDIAN, offset + delta);
        }
    }

    #[allow(dead_code)]
    pub fn get_vaddr_bounds(&self) -> (u64, u64) {
        let start = self.section_header.sh_addr(DENDIAN);
        let end = start + self.section_header.sh_size(DENDIAN);
        (start, end)
    }

    #[allow(dead_code)]
    pub fn get_file_bounds(&self) -> (u64, u64) {
        if self.section_header.sh_type(DENDIAN) == elf::SHT_NOBITS {
            return (0, 0);
        }
        let fstart = self.section_header.sh_offset(DENDIAN);
        let fsize = self.section_header.sh_size(DENDIAN);
        (fstart, fstart + fsize)
    }

    pub fn len() -> usize {
        std::mem::size_of::<Shdr64>()
    }
}
