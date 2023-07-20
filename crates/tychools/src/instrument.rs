use std::path::PathBuf;

use log::info;
use serde::{Deserialize, Serialize};
use serde_json;

use crate::allocator::PAGE_SIZE;
use crate::elf_modifier::{ModifiedELF, ModifiedSection, TychePhdrTypes};
use crate::page_table_mapper::generate_page_tables;

#[derive(Debug, Serialize, Deserialize)]
pub struct SegmentDescriptor {
    start: Option<u64>,
    size: usize,
    tpe: TychePhdrTypes,
    write: bool,
    exec: bool,
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

pub fn modify_binary(src: &PathBuf, dst: &PathBuf) {
    let data = std::fs::read(src).expect("Unable to read source file");
    info!("We read {} bytes from the file", data.len());
    let mut elf = ModifiedELF::new(&*data);

    // Create page tables.
    let (pts, nb_pages, cr3) = generate_page_tables(&*elf);
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
pub fn parse_binary(binary: &BinaryInstrumentation) -> Box<ModifiedELF> {
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
    elf
}

pub fn instrument_binary(manifest: &Manifest) {
    // Parse the untrusted part of the application.
    let mut untrusted_elf = if let Some(untrusted) = &manifest.untrusted_bin {
        let bin = parse_binary(untrusted);
        Some(bin)
    } else {
        None
    };
    // Parse the user binary if present.
    let mut user_elf = if let Some(user) = &manifest.user_bin {
        let mut bin = parse_binary(user);
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
        let mut bin = parse_binary(kern);
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
    let main_conf = if let (Some(ref mut user), Some(kern)) = (&mut user_elf, &kern_elf) {
        let user = user.as_mut();
        let kern = kern.as_ref();
        if user.overlap(kern) {
            panic!("The two binaries overlap");
        }
        user.merge(kern);
        if manifest.generate_pts {
            user.generate_page_tables(manifest.security);
        }
        user
    } else if let Some(ref mut user) = &mut user_elf {
        if manifest.generate_pts {
            user.generate_page_tables(manifest.security);
        }
        user
    } else if let Some(ref mut kern) = &mut kern_elf {
        if manifest.generate_pts {
            kern.generate_page_tables(manifest.security);
        }
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
    };
    let json = serde_json::to_string(&op).unwrap();
    log::info!("The generated json {}", json);
}
