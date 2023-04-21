use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

use log::info;
use object::Endianness;

use crate::allocator::PAGE_SIZE;
use crate::elf_modifier::{ModifiedELF, TychePhdrTypes};
use crate::page_table_mapper::generate_page_tables;

pub const DEFAULT_STACK_SIZE: usize = 0x5000;

pub fn modify_binary(src: &PathBuf, dst: &PathBuf) {
    let data = std::fs::read(src).expect("Unable to read source file");
    info!("We read {} bytes from the file", data.len());
    let mut elf = ModifiedELF::new(&*data);

    // Move default shared buffer into its own segment.
    elf.split_segment_at_section(
        ".tyche_shared_default_buffer",
        TychePhdrTypes::Shared as u32,
    )
    .expect("Failed to split section into segment");

    // Add the enclave stack as a segment.
    elf.append_nodata_segment(
        None,
        TychePhdrTypes::EnclStack as u32,
        object::elf::PF_R | object::elf::PF_W,
        DEFAULT_STACK_SIZE,
    );

    // TODO we could add a confidential heap here.
    // Or declare it as a section and move it into its own segment.

    // Create page tables.
    let (pts, nb_pages) = generate_page_tables(&*elf);
    elf.append_data_segment(
        Some(0),
        TychePhdrTypes::PageTables as u32,
        object::elf::PF_R | object::elf::PF_W,
        nb_pages * PAGE_SIZE,
        &pts,
    );

    // Let's write that thing out.
    let mut out: Vec<u8> = Vec::with_capacity(elf.len());
    let mut writer = object::write::elf::Writer::new(Endianness::Little, true, &mut out);
    elf.dump(&mut writer);

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(dst)
        .expect("Unable to open dest file");
    file.write(&*out).expect("Unable to dump the content");
}
