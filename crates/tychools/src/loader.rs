use core::slice;
use std::fs::File;
use std::num::NonZeroUsize;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use nix::ioctl_read;
use nix::sys::mman::{MapFlags, ProtFlags};
use object::elf;
use object::read::elf::{FileHeader, ProgramHeader};

use crate::elf_modifier::{ModifiedELF, ModifiedSegment, TychePhdrTypes, DENDIAN};
use crate::page_table_mapper::align_address;

// ————————————————————————— Constant declarations —————————————————————————— //
const TYCHE_DRIVER: &str = "/dev/tyche";

ioctl_read!(getphysoffset, b'a', b'c', MsgEnclaveInfo);
ioctl_read!(mprotect_enclave, b'a', b'e', MsgEnclaveProtect);
ioctl_read!(commit_enclave, b'a', b'd', MsgCommitEnclave);

// ————————————————————————————————— Types —————————————————————————————————— //

/// Typical structure to communicate with the driver.
#[repr(C)]
pub struct MsgEnclaveInfo {
    pub virtaddr: usize,
    pub physoffset: usize,
}

/// Structure to perform an mprotect with the driver.
#[repr(C)]
pub struct MsgEnclaveProtect {
    pub start: usize,
    pub size: usize,
    pub flags: libc::c_int,
    pub tpe: EnclaveSegmentType,
}

/// Commit message for an enclave.
#[repr(C)]
pub struct MsgCommitEnclave {
    start: usize,
    stack: usize,
    pts: usize,
}

/// The two types of segment understood by the driver.
#[repr(C)]
pub enum EnclaveSegmentType {
    Shared = 0,
    Confidential = 1,
}

#[repr(C)]
pub enum MemoryAccessRights {
    //MemActive = 1 << 0,
    //MemConfidential = 1 << 1,
    MemRead = 1 << 2,
    MemWrite = 1 << 3,
    MemExec = 1 << 4,
    MemSuper = 1 << 5,
}

/// Represents the enclave at load-time.
pub struct Enclave {
    pub elf: Box<ModifiedELF>,
    pub stack: u64,
    pub cr3: u64,
    pub fd: File,
    pub phys_offset: u64,
}

// ——————————————————————————————— Functions ———————————————————————————————— //

pub fn parse_and_run(file: &PathBuf) {
    let data = std::fs::read(file).expect("Unable to read source file");
    let mut enclave = Enclave {
        elf: ModifiedELF::new(&data),
        stack: 0,
        cr3: 0,
        fd: File::options()
            .read(true)
            .open(TYCHE_DRIVER)
            .expect("Unable to open tyche driver"),
        phys_offset: 0,
    };
    // Load the enclave.
    load(&mut enclave);

    //TODO run the enclave
}

/// load an instrumented binary.
pub fn load(encl: &mut Enclave) {
    let mut memsize: usize = usize::MIN;
    for seg in &encl.elf.segments {
        if !ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
            continue;
        }
        memsize += align_address(seg.program_header.p_memsz(DENDIAN) as usize);
    }
    log::debug!("The memory size to load is {:x}", memsize);

    // Register the enclave memory.
    let domain_memory = unsafe {
        nix::sys::mman::mmap(
            None,
            NonZeroUsize::new(memsize).unwrap(),
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_SHARED | MapFlags::MAP_POPULATE,
            encl.fd.as_raw_fd(),
            0,
        )
        .expect("Unable to allocate domain bytes")
    };

    // Get the physoffset to patch the page tables.
    let mut msg = MsgEnclaveInfo {
        virtaddr: 0,
        physoffset: 0,
    };
    unsafe {
        getphysoffset(encl.fd.as_raw_fd(), &mut msg).expect("Unable to get physoffset");
    }
    log::debug!("The physoffset is {:x}", msg.physoffset);

    // Let's fix the page tables now.
    encl.elf.fix_page_tables(msg.physoffset as u64);

    // Set the cr3 in the enclave.
    encl.cr3 = {
        let seg_pages = encl.elf.find_segments(TychePhdrTypes::PageTables);
        // It does not make sense for now to have two segments for page tables.
        assert!(seg_pages.len() == 1);
        seg_pages[0].program_header.p_vaddr(DENDIAN) + msg.physoffset as u64
    };

    // Finding the stack.
    encl.stack = {
        let kern_stack = encl.elf.find_segments(TychePhdrTypes::KernelStack);
        let user_stack = encl.elf.find_segments(TychePhdrTypes::UserStack);
        assert!(kern_stack.len() == 0 || kern_stack.len() == 1);
        assert!(user_stack.len() == 0 || user_stack.len() == 1);
        if kern_stack.len() == 1 {
            kern_stack[0].program_header.p_vaddr(DENDIAN)
        } else {
            user_stack[0].program_header.p_vaddr(DENDIAN)
        }
    };

    // Load each segment data.
    let content = {
        let byte_ptr = domain_memory as *mut u8;
        unsafe { slice::from_raw_parts_mut(byte_ptr, memsize) }
    };
    let mut curr_offset: usize = 0;
    for seg in &encl.elf.segments {
        if !ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
            continue;
        }
        let sz = align_address(seg.program_header.p_memsz(DENDIAN) as usize);
        content[curr_offset..curr_offset + seg.data.len()].copy_from_slice(&seg.data);
        curr_offset += sz;
    }
    assert_eq!(curr_offset, curr_offset);

    // Do the calls to mprotect now.
    let mut curr_va = domain_memory as usize;
    for seg in &encl.elf.segments {
        if !ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
            continue;
        }
        let sz = seg.program_header.p_memsz(DENDIAN);
        let mut args = MsgEnclaveProtect {
            start: curr_va,
            size: sz as usize,
            tpe: translate_type(seg.program_header.p_type(DENDIAN)).unwrap(),
            flags: translate_flags(
                seg.program_header.p_flags(DENDIAN),
                seg.program_header.p_type(DENDIAN),
            ),
        };
        unsafe {
            mprotect_enclave(encl.fd.as_raw_fd(), &mut args).unwrap();
        }
        curr_va += sz as usize;
    }

    // Ready to commit!
    let mut commit = MsgCommitEnclave {
        start: encl.elf.header.e_entry(DENDIAN) as usize,
        stack: encl.stack as usize,
        pts: encl.cr3 as usize,
    };
    unsafe {
        commit_enclave(encl.fd.as_raw_fd(), &mut commit).unwrap();
    }
}

fn translate_type(tpe: u32) -> Option<EnclaveSegmentType> {
    if let Some(value) = TychePhdrTypes::from_u32(tpe) {
        if value.is_confidential() {
            return Some(EnclaveSegmentType::Confidential);
        }
        return Some(EnclaveSegmentType::Shared);
    }
    return None;
}

fn translate_flags(flags: u32, tpe: u32) -> libc::c_int {
    let user = TychePhdrTypes::is_user(tpe);
    let mut res: libc::c_int = MemoryAccessRights::MemRead as libc::c_int;
    if !user {
        res |= MemoryAccessRights::MemSuper as libc::c_int;
    }
    if flags & elf::PF_W == elf::PF_W {
        res |= MemoryAccessRights::MemWrite as libc::c_int;
    }
    if flags & elf::PF_X == elf::PF_X {
        res |= MemoryAccessRights::MemExec as libc::c_int;
    }
    return res;
}
