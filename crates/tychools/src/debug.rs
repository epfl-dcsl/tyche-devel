use std::path::PathBuf;

use elfloader::*;
use log::info;

pub fn print_elf_segments(path: &PathBuf) {
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let binary = ElfBinary::new(slice).expect("Unable to parse elf.");
    for ph in binary.program_headers() {
        info!(
            "base = {:#x} size = {:#x} type = {:?} flags = {}",
            ph.virtual_addr(),
            ph.mem_size(),
            ph.get_type().unwrap(),
            ph.flags()
        );
    }
}
