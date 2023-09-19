use std::path::PathBuf;

use log::info;
use serde::{Deserialize, Serialize};
use serde_json::{self};

use crate::allocator::PAGE_SIZE;
use crate::elf_modifier::{ModifiedELF, ModifiedSection, TychePhdrTypes};
use crate::page_table_mapper::generate_page_tables;
use crate::tychools_const::{
    BRICKS_DATA_INFO, BRICKS_DATA_INFO_SIZE, DEFAULT_MEMPOOL_PNUM, DEFAULT_STACK_PNUM,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct SegmentDescriptor {
    start: Option<u64>,
    size: usize,
    tpe: TychePhdrTypes,
    write: bool,
    exec: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BricksInfo {
    memory_pool: bool,
    memory_pool_size: Option<u64>,
    user_stack: bool,
}

pub struct BricksData {
    memory_pool_start: u64,
    memory_pool_size: u64,
    user_rip_start: u64,
    user_stack_start: u64,
}

impl BricksData {
    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut vec: Vec<u8> = Vec::new();
        vec.extend(self.memory_pool_start.to_le_bytes().to_vec());
        vec.extend(self.memory_pool_size.to_le_bytes().to_vec());
        vec.extend(self.user_rip_start.to_le_bytes().to_vec());
        vec.extend(self.user_stack_start.to_le_bytes().to_vec());
        vec
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BinaryOperation {
    SectionToSegment(String, TychePhdrTypes),
    AddSegment(SegmentDescriptor),
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy)]
pub enum Security {
    Confidential = 1,
    Sandbox = 2,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BinaryInstrumentation {
    /// Path to the binary.
    path: String,
    /// Extra operations to perform on the binary.
    ops: Option<Vec<BinaryOperation>>,
    /// Bricks info
    bricks_info: Option<BricksInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MappingPageTables {
    /// Do we need to map the page tables
    map: bool,
    /// If we want to map it, from which address
    virt_addr_start: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Untrusted part of the application.
    untrusted_bin: Option<BinaryInstrumentation>,
    /// User binary
    user_bin: Option<BinaryInstrumentation>,
    /// Kernel binary
    kern_bin: Option<BinaryInstrumentation>,
    /// Is this a sandbox or an enclave.
    #[serde(default = "default_security")]
    security: Security,
    /// Should we generate page tables.
    #[serde(default = "default_ops_true")]
    generate_pts: bool,
    /// Options for mapping page tables
    map_page_tables: Option<MappingPageTables>,
    /// Should we sort Phdrs
    #[serde(default = "default_ops_false")]
    sort_phdrs: bool,
    /// Destination ELF file.
    output: String,
}

fn default_ops_true() -> bool {
    true
}

fn default_ops_false() -> bool {
    false
}

fn default_security() -> Security {
    Security::Confidential
}

fn should_we_map(map: &Option<MappingPageTables>) -> bool {
    if let Some(mp) = map {
        mp.map
    } else {
        false
    }
}

const DEFAULT_VIRT_ADDR_START: usize = 0x800000000000;

fn map_page_table_virt_addr(map: &Option<MappingPageTables>) -> usize {
    if let Some(mp) = map {
        if let Some(addr) = mp.virt_addr_start {
            return addr;
        }
        DEFAULT_VIRT_ADDR_START
    } else {
        0
    }
}

pub fn decode_map(map: &Option<MappingPageTables>) -> (bool, usize) {
    (should_we_map(map), map_page_table_virt_addr(map))
}

pub fn modify_binary(src: &PathBuf, dst: &PathBuf) {
    let data = std::fs::read(src).expect("Unable to read source file");
    info!("We read {} bytes from the file", data.len());
    let mut elf = ModifiedELF::new(&*data);

    // Create page tables.
    // TODO do we need an option to choose mapping of page tables here
    let (pts, nb_pages, cr3) = generate_page_tables(&*elf, &None);
    elf.append_data_segment(
        Some(cr3 as u64),
        TychePhdrTypes::PageTablesConf as u32,
        object::elf::PF_R | object::elf::PF_W,
        nb_pages * PAGE_SIZE,
        &pts,
    );

    // Let's write that thing out.
    elf.dump_to_file(dst, true);
}

pub fn instrument_with_manifest(src: &PathBuf) {
    // Parse the manifest.
    let manifest: Manifest = {
        let data = std::fs::read(src).expect("Unable to read source file");
        let content = String::from_utf8(data).expect("Unable to convert data to string");
        serde_json::from_str(&content).expect("Failed to parse JSON")
    };
    instrument_binary(&manifest);
}

/// Parse singular binary instrumentation description and applies its operations.
pub fn parse_binary(
    binary: &BinaryInstrumentation,
    user_bin: &Option<Box<ModifiedELF>>,
) -> Box<ModifiedELF> {
    let data = std::fs::read(PathBuf::from(&binary.path)).expect("Unable to read the binary");
    let mut elf = ModifiedELF::new(&*data);

    // Apply all the operations.
    if let Some(operations) = &binary.ops {
        for op in operations {
            match &op {
                BinaryOperation::SectionToSegment(section, tpe) => {
                    elf.split_segment_at_section(section, *tpe as u32, &data)
                        .expect("Unable to perform the desired split operation");
                }
                BinaryOperation::AddSegment(descr) => {
                    let mut rights = object::elf::PF_R;
                    if descr.write {
                        rights |= object::elf::PF_W;
                    }
                    if descr.exec {
                        rights |= object::elf::PF_X;
                    }
                    elf.append_nodata_segment(descr.start, descr.tpe as u32, rights, descr.size);
                }
            }
        }
    }

    // Apply Bricks info
    if let Some(bricks_info) = &binary.bricks_info {
        log::debug!("Bricks info!");
        let mut virt_addr: u64 = BRICKS_DATA_INFO + BRICKS_DATA_INFO_SIZE;
        let virt_addr_info: u64 = BRICKS_DATA_INFO;
        let mut bricks_data = BricksData {
            memory_pool_size: 0,
            memory_pool_start: 0,
            user_rip_start: 0,
            user_stack_start: 0,
        };
        let rights = object::elf::PF_R | object::elf::PF_W;
        // if there is requirement for memory pool, add it
        if bricks_info.memory_pool {
            bricks_data.memory_pool_start = virt_addr;
            if let Some(sz) = bricks_info.memory_pool_size {
                bricks_data.memory_pool_size = sz;
            } else {
                bricks_data.memory_pool_size = DEFAULT_MEMPOOL_PNUM;
            }
            let byte_size = bricks_data.memory_pool_size * PAGE_SIZE as u64;
            elf.append_nodata_segment(
                Some(virt_addr as u64),
                TychePhdrTypes::KernelConfidential as u32,
                rights,
                byte_size as usize,
            );
            virt_addr += byte_size;
        }
        // if there is requirement for stack, add it
        if bricks_info.user_stack {
            bricks_data.user_stack_start = virt_addr;
            elf.append_nodata_segment(
                Some(virt_addr),
                TychePhdrTypes::UserConfidential as u32,
                rights,
                DEFAULT_STACK_PNUM as usize * PAGE_SIZE,
            );
        }
        if let Some(usr) = user_bin {
            bricks_data.user_rip_start = usr.elf_start();
        }
        // converting Bricks data to vector for segment
        let vec_data: Vec<u8> = bricks_data.to_le_bytes();
        elf.append_data_segment(
            Some(virt_addr_info),
            TychePhdrTypes::KernelConfidential as u32,
            object::elf::PF_R,
            PAGE_SIZE as usize,
            &vec_data,
        );
    }

    elf
}

pub fn instrument_binary(manifest: &Manifest) {
    // Parse the untrusted part of the application.
    let mut untrusted_elf = if let Some(untrusted) = &manifest.untrusted_bin {
        let bin = parse_binary(untrusted, &None);
        Some(bin)
    } else {
        None
    };
    // Parse the user binary if present.
    let mut user_elf = if let Some(user) = &manifest.user_bin {
        let mut bin = parse_binary(user, &None);
        if manifest.security == Security::Confidential {
            bin.mark(TychePhdrTypes::UserConfidential);
        } else {
            bin.mark(TychePhdrTypes::UserShared);
        }
        Some(bin)
    } else {
        None
    };
    // Parse the kernel binary if present.
    let mut kern_elf = if let Some(kern) = &manifest.kern_bin {
        let mut bin = parse_binary(kern, &user_elf);
        if manifest.security == Security::Confidential {
            bin.mark(TychePhdrTypes::KernelConfidential);
        } else {
            bin.mark(TychePhdrTypes::KernelShared);
        }
        Some(bin)
    } else {
        None
    };

    // Complex case.
    let main_conf = if let (Some(ref mut user), Some(kern)) = (&mut user_elf, &mut kern_elf) {
        let user = user.as_mut();
        let kern = kern.as_mut();
        if user.overlap(kern) {
            panic!("The two binaries overlap");
        }
        kern.set_attestation_hash();
        user.merge(kern);
        if manifest.generate_pts {
            user.generate_page_tables(manifest.security, &manifest.map_page_tables);
        }
        user
    } else if let Some(ref mut user) = &mut user_elf {
        if manifest.generate_pts {
            user.generate_page_tables(manifest.security, &manifest.map_page_tables);
        }
        user
    } else if let Some(ref mut kern) = &mut kern_elf {
        if manifest.generate_pts {
            kern.generate_page_tables(manifest.security, &manifest.map_page_tables);
        }
        kern.set_attestation_hash();
        kern
    } else {
        panic!("We had nothing to instrument");
    };

    let (final_output, sort_phdrs) = if let Some(ref mut bin) = &mut untrusted_elf {
        let conf_content = main_conf.dump(manifest.sort_phdrs);
        let size_so_far = bin.len();
        bin.add_section_header(&ModifiedELF::construct_shdr(
            0,
            object::elf::SHT_NOTE,
            object::elf::SHF_MASKOS as u64,
            size_so_far as u64 + ModifiedSection::len() as u64,
            conf_content.len() as u64,
            0,
            conf_content.len() as u64,
            0,
        ));
        bin.secret_data.extend(conf_content);
        (&mut (**bin), manifest.sort_phdrs)
    } else {
        (main_conf, manifest.sort_phdrs)
    };

    // Finally write the content to the provided file.
    final_output.dump_to_file(&PathBuf::from(&manifest.output), sort_phdrs);
}

pub fn print_enum() {
    let op = BinaryInstrumentation {
        path: "templates/app".to_string(),
        ops: Some(vec![
            BinaryOperation::AddSegment(SegmentDescriptor {
                start: None,
                size: 0x2000,
                tpe: TychePhdrTypes::UserStackConf,
                write: true,
                exec: false,
            }),
            BinaryOperation::AddSegment(SegmentDescriptor {
                start: None,
                size: 0x2000,
                tpe: TychePhdrTypes::UserShared,
                write: true,
                exec: false,
            }),
        ]),
        bricks_info: None,
    };
    let json = serde_json::to_string(&op).unwrap();
    log::info!("The generated json {}", json);
}
