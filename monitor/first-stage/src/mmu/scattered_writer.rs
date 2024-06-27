use alloc::vec::Vec;

use mmu::frame_allocator::PhysRange;

/// Writer-style abstraction to write to scattered physical memory
/// As we are no-std, this does not actually implement the writer trait though
/// Assumes identity mapping
pub struct ScatteredIdMappedBuf {
    /// Memory that backs this buffer
    phys_mem: Vec<PhysRange>,
    /// Translate phys addr to virt, assuming identity mapping
    phys_to_virt_offset: usize,
    /// Internal. Index that tracks which range in `phys_mem` we are currently in
    phys_mem_idx: usize,
    /// Internal. Offset inside current phys mem range
    local_offset: usize,
}

impl ScatteredIdMappedBuf {
    ///
    /// # Arguments
    /// - `phys_mem` physical memory ranges that this buffer writes to
    /// - `offset_in_first_page` : start at this offset in the first page of `phys_mem`
    /// - `phys_to_virt_offset` : Offset to translate virt addr to phys addr, assuming identity mapping
    pub fn new(
        phys_mem: Vec<PhysRange>,
        phys_to_virt_offset: usize,
        offset_in_first_page: usize,
    ) -> Self {
        Self {
            phys_mem,
            phys_to_virt_offset,
            phys_mem_idx: 0,
            local_offset: offset_in_first_page,
        }
    }

    /// Size of the buffer in bytes
    pub fn size(&self) -> usize {
        self.phys_mem.iter().map(|r| r.size()).sum()
    }

    /// Write from `source` into the buffer
    /// In case of error, the number of successfully written bytes are returned
    pub fn write(&mut self, source: &[u8]) -> Result<(), usize> {
        let mut written_bytes = 0;
        while written_bytes < source.len() {
            let cur_phys = self.phys_mem[self.phys_mem_idx];
            let cur_phys_remaining_bytes = cur_phys.size() - self.local_offset;
            if cur_phys_remaining_bytes == 0 {
                //have remaining bytes to write but no more mem -> error
                if self.phys_mem_idx >= (self.phys_mem.len() - 1) {
                    return Err(written_bytes);
                }
                //move to next phys mem range
                self.phys_mem_idx += 1;
                self.local_offset = 0;
                continue;
            }
            //if we are here, the current phys mem range has room for `cur_phys_remaining_bytes`
            //compute amount of bytes to copy in this iteration
            let remaining_bytes_in_source = source.len() - written_bytes;
            let chunk_size = if remaining_bytes_in_source < cur_phys_remaining_bytes {
                remaining_bytes_in_source
            } else {
                cur_phys_remaining_bytes
            };
            //copy
            unsafe {
                let dest = core::slice::from_raw_parts_mut(
                    (cur_phys.start.as_usize() + self.local_offset + self.phys_to_virt_offset)
                        as *mut u8,
                    chunk_size,
                );

                dest.copy_from_slice(&source[written_bytes..(written_bytes + chunk_size)])
            }
            //update state vars
            written_bytes += chunk_size;
            self.local_offset += chunk_size;
            assert!(self.local_offset <= cur_phys.size());
        }
        //while loop terminated -> we have copied all bytes
        Ok(())
    }

    ///Convenience wrapper around `write` that writes `value` for the specified `count`
    pub fn fill(&mut self, value: u8, count: usize) -> Result<(), usize> {
        let source = [value; 1];
        for i in 0..count {
            if let Err(_) = self.write(&source) {
                return Err(count - i);
            }
        }
        Ok(())
    }
}
