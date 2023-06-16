use std::path::PathBuf;

use object::read::elf::ProgramHeader;
use sha2::{Digest, Sha256};

use crate::elf_modifier::{ModifiedELF, ModifiedSegment, TychePhdrTypes, DENDIAN};

/// For the moment we only measure confidential segments.
pub fn attest(src: &PathBuf, offset: u64) {
    let data = std::fs::read(src).expect("Unable to read source file");
    let mut hasher = Sha256::new();
    let mut enclave = ModifiedELF::new(&data);
    enclave.fix_page_tables(offset);
    for seg in &enclave.segments {
        if ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
            if let Some(tpe) = TychePhdrTypes::from_u32(seg.program_header.p_type(DENDIAN)) {
                if (!tpe.is_confidential()) || seg.data.is_empty() {
                    continue;
                }
                hasher.update(&seg.data);
            }
        }
    }
    let result = hasher.finalize();
    log::info!("Computed hash:");
    log::info!("{}", format!("{:x}", result));
}
