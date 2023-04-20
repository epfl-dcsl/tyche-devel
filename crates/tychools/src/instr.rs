use object::elf::PT_LOAD;
use object::read::elf::{FileHeader, ProgramHeader, SectionHeader};
use object::{elf, Endian, Endianness, U16Bytes, U32Bytes, U64Bytes};

#[derive(Debug)]
pub enum ErrorBin {
    SectionMissing = 1,
    SegmentMissing = 2,
    UnalignedAddress = 3,
}

pub const PAGE_SIZE: u64 = 0x1000;

#[derive(Debug)]
#[allow(dead_code)]
#[repr(u32)]
pub enum TychePhdrTypes {
    PtPageTables = 0x60000000,
    PtStack = 0x60000001,
    PtShared = 0x60000002,
    PtCondidential = 0x60000003,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ModifiedSection {
    idx: usize,
    name: String,
    section_header: elf::SectionHeader64<Endianness>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ModifiedSegment {
    idx: usize,
    program_header: elf::ProgramHeader64<Endianness>,
}

#[derive(Debug)]
pub struct MemoryLayout {
    min_addr: u64,
    max_addr: u64,
}

#[derive(Debug)]
pub struct ModifiedELF {
    header: elf::FileHeader64<Endianness>,
    segments: Vec<ModifiedSegment>,
    sections: Vec<ModifiedSection>,
    layout: MemoryLayout,
    data: Vec<u8>,
}

fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
    }
}

impl ModifiedELF {
    pub fn new(data: &[u8]) -> Box<ModifiedELF> {
        // Parse the header.
        let hdr = elf::FileHeader64::<Endianness>::parse(data).expect("Unable to parse the data");

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
            .program_headers(Endianness::Little, data)
            .expect("Unable to parse segments");

        for (idx, seg) in segs.iter().enumerate() {
            melf.segments.push(ModifiedSegment {
                idx,
                program_header: seg.clone(),
            });

            // Find the virtual memory boundaries.
            if seg.p_type(Endianness::Little) == PT_LOAD {
                let start = seg.p_vaddr(Endianness::Little);
                let end = start + seg.p_memsz(Endianness::Little);
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
            .section_headers(Endianness::Little, data)
            .expect("Unable to parse sections");
        let strings = hdr
            .section_strings(Endianness::Little, data, secs)
            .expect("Unable to get the strings");

        for (idx, sec) in secs.iter().enumerate() {
            let name = String::from_utf8(
                sec.name(Endianness::Little, strings)
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
        let data_start: usize = hdr.e_ehsize(Endianness::Little) as usize
            + hdr.e_phentsize(Endianness::Little) as usize
                * hdr.e_phnum(Endianness::Little) as usize;
        let data_end = hdr.e_shoff(Endianness::Little) as usize;

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
        std::mem::size_of::<elf::FileHeader64<Endianness>>()
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
    ) -> elf::ProgramHeader64<Endianness> {
        elf::ProgramHeader64::<Endianness> {
            p_type: U32Bytes::new(Endianness::Little, seg_type),
            p_flags: U32Bytes::new(Endianness::Little, flags),
            p_offset: U64Bytes::new(Endianness::Little, offset),
            p_vaddr: U64Bytes::new(Endianness::Little, vaddr),
            p_paddr: U64Bytes::new(Endianness::Little, 0),
            p_filesz: U64Bytes::new(Endianness::Little, filesz),
            p_memsz: U64Bytes::new(Endianness::Little, memsz),
            p_align: U64Bytes::new(Endianness::Little, align),
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
    ) -> elf::SectionHeader64<Endianness> {
        elf::SectionHeader64::<Endianness> {
            sh_name: U32Bytes::new(Endianness::Little, name),
            sh_type: U32Bytes::new(Endianness::Little, sec_type),
            sh_flags: U64Bytes::new(Endianness::Little, flags),
            sh_addr: U64Bytes::new(Endianness::Little, vaddr),
            sh_offset: U64Bytes::new(Endianness::Little, offset),
            sh_size: U64Bytes::new(Endianness::Little, memsz),
            sh_info: U32Bytes::new(Endianness::Little, 0),
            sh_addralign: U64Bytes::new(Endianness::Little, align),
            sh_entsize: U64Bytes::new(Endianness::Little, filesz),
            sh_link: U32Bytes::new(Endianness::Little, 0),
        }
    }

    pub fn add_segment(
        &mut self,
        vaddr: Option<u64>,
        seg_type: u32,
        flags: u32,
        size: usize,
        data: Option<&Vec<u8>>,
    ) {
        let (foff, fsize): (u64, u64) = match data {
            None => (0, 0),
            Some(content) => {
                let foff = self.data.len();
                let fsize = content.len();
                self.data.extend(content);
                (foff as u64, fsize as u64)
            }
        };
        let phdr = Self::construct_phdr(
            seg_type,
            flags,
            foff,
            fsize,
            vaddr.unwrap_or(self.layout.max_addr),
            size as u64,
            0x1000,
        );

        // Update the max address.
        if let Some(addr) = vaddr {
            if addr + size as u64 > self.layout.max_addr {
                self.layout.max_addr = addr + size as u64;
            }
        } else {
            self.layout.max_addr += size as u64;
        }
        // How much we insert.
        let delta: u64 = ModifiedSegment::len() as u64;
        // Offsets that are affected.
        let affected: u64 = (self.len_hdr() + self.len_phdrs()) as u64;

        // Fix segment offsets.
        for seg in &mut self.segments {
            seg.patch_offset(delta, affected);
        }

        // Fix section offsets.
        for sec in &mut self.sections {
            sec.patch_offset(delta, affected);
        }

        // Add the segment.
        self.segments.push(ModifiedSegment {
            idx: self.segments.len(),
            program_header: phdr,
        });

        // Fix the header.
        self.header.e_phnum = U16Bytes::new(Endianness::Little, self.segments.len() as u16);
        let shoff = self.header.e_shoff(Endianness::Little) + fsize;
        self.header.e_shoff = U64Bytes::new(Endianness::Little, shoff + delta);

        // We are done!
    }

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
        let phdr = Self::construct_phdr(seg_type, flags, 0, 0, addr, size as u64, PAGE_SIZE);

        // Simply add it to the segments.
        self.add_segment_header(&phdr);
    }

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
        let shoff = self.header.e_shoff(Endianness::Little) + fsize;
        self.header.e_shoff = U64Bytes::new(Endianness::Little, shoff);

        // Create a header.
        let phdr = Self::construct_phdr(seg_type, flags, foff, fsize, addr, size as u64, PAGE_SIZE);

        self.add_segment_header(&phdr);
    }

    pub fn add_segment_header(&mut self, phdr: &elf::ProgramHeader64<Endianness>) {
        let delta = ModifiedSegment::len() as u64;
        let affected = (self.len_hdr() + self.len_phdrs()) as u64;
        self.segments.push(ModifiedSegment {
            idx: self.segments.len(),
            program_header: phdr.clone(),
        });

        for seg in &mut self.segments {
            seg.patch_offset(delta, affected);
        }
        for sec in &mut self.segments {
            sec.patch_offset(delta, affected);
        }

        // Patch the header.
        self.header.e_phnum = U16Bytes::new(Endianness::Little, self.segments.len() as u16);
        let shoff = self.header.e_shoff(Endianness::Little);
        self.header.e_shoff = U64Bytes::new(Endianness::Little, shoff + delta);

        // All done!
    }

    /// This function relocates a section into its own segment.
    pub fn split_segment_at_section(
        &mut self,
        sec_name: &str,
        seg_type: u32,
    ) -> Result<(), ErrorBin> {
        // Find the section with the right name.
        let sec_to_move = match self.sections.iter().find(|s| s.name == sec_name) {
            Some(s) => s,
            None => {
                return Err(ErrorBin::SectionMissing);
            }
        };

        // Find the file content.
        let (fstart, fend) = match sec_to_move.section_header.file_range(Endianness::Little) {
            Some(a) => a,
            None => (0, 0),
        };

        // Get virtual boundaries.
        let (sec_start, sec_end) = sec_to_move.get_vaddr_bounds();
        if sec_start % PAGE_SIZE != 0 || sec_end % PAGE_SIZE != 0 {
            log::error!(
                "Section {} has unaligned start {:x} or end {:x}",
                sec_to_move.name,
                sec_start,
                sec_end
            );
            return Err(ErrorBin::UnalignedAddress);
        }

        // Find the segment that contains it.
        let seg: &mut ModifiedSegment = match self.segments.iter_mut().find(|s| {
            let (start, end) = s.get_vaddr_bounds();
            start <= sec_start && end >= sec_end
        }) {
            Some(s) => s,
            None => {
                return Err(ErrorBin::SegmentMissing);
            }
        };

        // Figure out the split.
        let (seg_start, seg_end) = seg.get_vaddr_bounds();
        if sec_start == seg_start && sec_end == seg_end {
            // Nothing to split, just change the p_type.
            seg.program_header.p_type = U32Bytes::new(Endianness::Little, seg_type);
            return Ok(());
        }

        // It is at the start of the segment.
        /*if sec_start == seg_start {
            let mut new_hdr = seg.program_header.clone();
            new_hdr.p_type = U32Bytes::new(Endianness::Little, seg_type);
            let fsize = u64::min(sec_end - sec_start, fstart - fend);
            new_hdr.program_header.
        }*/

        Ok(())
    }
}

impl ModifiedSegment {
    pub fn patch_offset(&mut self, delta: u64, affected: u64) {
        let offset = self.program_header.p_offset(Endianness::Little);
        if offset >= affected {
            self.program_header.p_offset = U64Bytes::new(Endianness::Little, offset + delta);
        }
    }

    pub fn get_vaddr_bounds(&self) -> (u64, u64) {
        let start = self.program_header.p_vaddr(Endianness::Little);
        let end = start + self.program_header.p_memsz(Endianness::Little);
        (start, end)
    }

    pub fn get_file_bounds(&self) -> (u64, u64) {
        let fstart = self.program_header.p_offset(Endianness::Little);
        let fsize = self.program_header.p_filesz(Endianness::Little);
        (fstart, fsize)
    }

    pub fn len() -> usize {
        std::mem::size_of::<elf::ProgramHeader64<Endianness>>()
    }
}

impl ModifiedSection {
    pub fn patch_offset(&mut self, delta: u64, affected: u64) {
        let offset = self.section_header.sh_offset(Endianness::Little);
        if offset >= affected {
            self.section_header.sh_offset = U64Bytes::new(Endianness::Little, offset + delta);
        }
    }

    pub fn get_vaddr_bounds(&self) -> (u64, u64) {
        let start = self.section_header.sh_addr(Endianness::Little);
        let end = start + self.section_header.sh_size(Endianness::Little);
        (start, end)
    }

    pub fn len() -> usize {
        std::mem::size_of::<elf::SectionHeader64<Endianness>>()
    }
}
