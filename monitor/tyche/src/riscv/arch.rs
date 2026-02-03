//! Architecture specific structures

use core::arch::asm;
use core::ptr;

use riscv_csrs::*;
use riscv_sbi::*;
use riscv_tyche::*;
use riscv_utils::*;

use crate::println;
use crate::riscv::platform::machine_trap_handler;

/// MPRV
//pub const MPRV_OFFSET: usize = 17;
//pub const MPRV_FILTER: usize = 0b1 << MPRV_OFFSET;
pub const MPP_OFFSET: usize = 11;
pub const MPP_FILTER: usize = 0b11 << MPP_OFFSET;
pub const ILLEGAL_INSTRUCTION: usize = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    /// User
    #[default]
    U,
    /// Supervisor
    S,
    /// Machine
    M,
}

// ——————————————————————— Width of Access Instructions —————————————————————— //

/// Represents different data widths:
///  - `Byte`: 8 bits (1 byte)
///  - `Byte2`: 16 bits (2 bytes)
///  - `Byte4`: 32 bits (4 bytes)
///  - `Byte8`: 64 bits (8 bytes)
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Width {
    Byte = 8,
    Byte2 = 16,
    Byte4 = 32,
    Byte8 = 64,
}

impl Width {
    pub fn to_bits(self) -> usize {
        self as usize
    }

    pub fn to_bytes(self) -> usize {
        self.to_bits() / 8
    }
}

impl From<usize> for Width {
    fn from(value: usize) -> Self {
        match value {
            8 => Width::Byte,
            16 => Width::Byte2,
            32 => Width::Byte4,
            64 => Width::Byte8,
            _ => panic!("Invalid width value"),
        }
    }
}

macro_rules! asm_mprv_mem_op {
    ($instr:literal, $addr:expr, $value:ident) => {{
        let mut success = 1;
        let mcause_val: usize;
        asm!(
            "csrr {old_mtvec}, mtvec", // Save current mtvec
            "csrw mtvec, {mtvec}",     // Install our MPRV-aware trap handler

            // Enable MPRV
            //
            // From that point onward, load and store instructions use the privileges in mstatus.MPP
            // when computing addresses and access rights. In other words, the loads and store will
            // behaves as if they were executed from S or U-mode.
            "csrs mstatus, {mprv_bit}",

            // The 'norvc' guarantees that instructions are 4 bytes wide.
            // This prevents the compiler from using compressed load/stores.
            // The trap handler uses this assumption when computing the return address.
            ".option push",
            ".option norvc",
            concat!($instr, " {rd}, 0({addr})"),
            ".option pop",

            "csrc mstatus, {mprv_bit}", // Disable MPRV
            "csrw mtvec, {old_mtvec}",  // Restore mtvec
            "csrr {mcause_val}, mcause",  // Reading mcause to log on trap 
            old_mtvec = out(reg) _,
            mtvec = in(reg) (_mprv_trap_handler as usize),
            addr = in(reg) $addr,
            rd = inout(reg) $value,
            mprv_bit = in(reg) 1 << mstatus::MPRV,
            inout("t5") success, // The trap handler sets t5 to 0 when trapping
            mcause_val = out(reg) mcause_val,
        );
        // Return true if the access succeeded
        assert_eq!(success, 1, "MPRV Mem Op Trapped with cause: 0x{:x} :(", mcause_val); 
        true
    }};
}

/// A load (register-based) instruction.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LoadInstr {
    pub rd: usize,
    pub rs1: usize,
    pub imm: isize,
    pub len: Width,
    pub is_compressed: bool,
    pub is_unsigned: bool,
}

/// A store (register-based) instruction.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StoreInstr {
    pub rs2: usize,
    pub rs1: usize,
    pub imm: isize,
    pub len: Width,
    pub is_compressed: bool,
}

pub fn init(hartid: usize) {
    unsafe {
        asm!("csrw mscratch, {}", in(reg) TYCHE_STACK_POINTER[hartid]);
    }

    // Configuring mtvec direct base address to point to Tyche's trap handler.
    let mtvec_ptr = machine_trap_handler as *const ();
    //log::info!("mtvec_ptr to be set by Tyche {:p}", mtvec_ptr);
    set_mtvec(mtvec_ptr);
}

// ------------------------------ Trap Handler Setup -------------------------- //

pub fn set_mtvec(addr: *const ()) {
    unsafe {
        asm!("csrw mtvec, {}", in(reg) addr);
    }

    let mut mtvec: usize;
    unsafe {
        asm!("csrr {}, mtvec", out(reg) mtvec);
    }

    //log::info!("Updated mtvec {:x}", mtvec);
}

pub unsafe fn get_raw_faulting_instr(mcause: usize, mtval: usize, mepc: usize, mode: Mode) -> usize {
    // First, try mtval and check if it contains an instruction
    if mcause == ILLEGAL_INSTRUCTION as usize && mtval != 0 {
        return mtval;
    }

    // Then as a fallback we read the instruction directly from memory
    match mode {
        Mode::M => {    
            // The virtual firmware runs in U-mode without virtual memory, we can read memory
            // directly
            //
            // NOTE: this access might fault, in the future we might want to use our safer
            // [Arch::read_bytes_from_mode] function which catches traps during reads. However
            // doing so would slow down that path quite a lot until we have an optimized
            // [Arch::read_bytes_from_mode] implementation.
            let instr_ptr = mepc as *const u32;
            let instr = unsafe { ptr::read_unaligned(instr_ptr) };
            instr as usize
        }
        mode => {
            // The instructions come from the payload, therefore virtual memory might be enabled.
            // We need to read the instructions using MPRV.
            let mut instr: [u8; 4] = [0, 0, 0, 0];
            let instr_ptr = mepc as *const u8;
            unsafe { read_bytes_from_mode(instr_ptr, &mut instr, mode).unwrap() };
            u32::from_le_bytes(instr) as usize
        }
    }
}

/// Decodes a raw read RISC-V instruction.
pub fn decode_load(raw: usize) -> LoadInstr {
    match extract_last_two_bits(raw) {
        0b11 => decode_uncompressed_load(raw),
        // Register-based load and store instructions for C set start with 0b00
        0b00 => decode_register_based_compressed_load(raw),
        // Stack-based load and store instructions for C set start with 0b10
        0b10 => todo!("Decode stack based C load"),
        _ => unreachable!(),
    }
}

/// Decodes a raw write RISC-V instruction.
pub fn decode_store(raw: usize) -> StoreInstr {
    match extract_last_two_bits(raw) {
        0b11 => decode_uncompressed_store(raw),
        // Register-based load and store instructions for C set start with 0b00
        0b00 => decode_register_based_compressed_store(raw),
        // Stack-based load and store instructions for C set start with 0b10
        0b10 => todo!("Decode stack based C store"),
        _ => unreachable!(),
    }
}

/// Copies dest.len() bytes from src to dest, using the provided mode to read from src.
///
/// This function can be useful to copy bytes from the virtual address space of a lower
/// privileged mode, to a buffer in M-mode.
///
/// Returns whether the copy succeeded or not (for example, the copy might not succeed if we try
/// to read an address not accessible from the given mode).
pub unsafe fn read_bytes_from_mode(src: *const u8, dest: &mut [u8], mode: Mode) -> Result<(), ()> {
    let mut addr = src as usize;

    // Save the state of exception-related CSRs, as we might overwrite them if an error occurs
    let mut prev_mcause: usize;
    let mut prev_mepc: usize;
    let mut prev_mstatus: usize;
    unsafe {
        asm!("csrr {}, mcause", out(reg) prev_mcause);
        asm!("csrr {}, mepc", out(reg) prev_mepc);
        asm!("csrr {}, mstatus", out(reg) prev_mstatus);
    }

    unsafe {
        // Set mstatus.MPP to mode
        // let prev_mode = set_mpp(mode); -- Neelu: I don't think we need it 
        for dest_byte in dest {
            let mut byte_read: u8 = 0;
            let success = asm_mprv_mem_op!("lbu", addr, byte_read);

            // if dest.len() == 4 {
            //     log::info!("Address 0x{:x} byte_read 0x{:x}", addr, byte_read);
            // }

            if !success {
                // Restore previous registers
                asm!("csrw mcause, {}", in(reg) prev_mcause);
                asm!("csrw mepc, {}", in(reg) prev_mepc);
                asm!("csrw mstatus, {}", in(reg) prev_mstatus);
                return Err(());
            }

            *dest_byte = byte_read;
            addr += 1;
        }

        // set_mpp(prev_mode); -- Neelu: I don't think we need it 
        Ok(())
    }
}

/// Copies src.len() bytes from src to dest, using the provided mode to write to src.
///
/// This function can be useful to copy bytes from the virtual address space of a lower
/// privileged mode, to a buffer in M-mode.
///
/// Returns whether the copy succeeded or not (for example, the copy might not succeed if we try
/// to read an address not accessible from the given mode).
pub unsafe fn store_bytes_from_mode(src: &[u8], dest: *mut u8, mode: Mode) -> Result<(), ()> {
    let mut dest = dest as usize;

    // Save the state of exception-related CSRs, as we might overwrite them if an error occurs
    let mut prev_mcause: usize;
    let mut prev_mepc: usize;
    let mut prev_mstatus: usize;
    unsafe {
        asm!("csrr {}, mcause", out(reg) prev_mcause);
        asm!("csrr {}, mepc", out(reg) prev_mepc);
        asm!("csrr {}, mstatus", out(reg) prev_mstatus);
    }

    unsafe {
        // Set mstatus.MPP to mode
        //let prev_mode = set_mpp(mode);
        for src_byte in src {
            let mut byte_value: u8 = *src_byte;
            let success = asm_mprv_mem_op!("sb", dest, byte_value);
            let _ = byte_value; // Silence warning, 'sb' does not update byte_value

            if !success {
                // Restore previous registers
                asm!("csrw mcause, {}", in(reg) prev_mcause);
                asm!("csrw mepc, {}", in(reg) prev_mepc);
                asm!("csrw mstatus, {}", in(reg) prev_mstatus);
                return Err(());
            }

            dest += 1;
        }

        //set_mpp(prev_mode);
        Ok(())
    }
}

/// Returns the mode corresponding to the bit pattern
pub fn parse_mpp_return_mode(mstatus_reg: usize) -> Mode {
    match (mstatus_reg & MPP_FILTER) >> MPP_OFFSET {
        0 => Mode::U,
        1 => Mode::S,
        3 => Mode::M,
        _ => panic!("Unknown mode!"),
    }
}

fn extract_last_two_bits(value: usize) -> usize {
    value & 0b11
}

fn decode_uncompressed_load(raw: usize) -> LoadInstr {
    let func3 = (raw >> 12) & 0b111;
    let rd = (raw >> 7) & 0b11111;
    let rs1 = (raw >> 15) & 0b11111;
    let imm = bits_to_int(raw, 20, 31);

    // let rs1 = Register::from(rs1);
    // let rd = Register::from(rd);

    match func3 {
        0b000 => LoadInstr {
            rd,
            rs1,
            imm,
            len: Width::from(8),
            is_compressed: false,
            is_unsigned: false,
        },
        0b001 => LoadInstr {
            rd,
            rs1,
            imm,
            len: Width::from(16),
            is_compressed: false,
            is_unsigned: false,
        },
        0b010 => LoadInstr {
            rd,
            rs1,
            imm,
            len: Width::from(32),
            is_compressed: false,
            is_unsigned: false,
        },
        0b011 => LoadInstr {
            rd,
            rs1,
            imm,
            len: Width::from(64),
            is_compressed: false,
            is_unsigned: false,
        },
        0b100 => LoadInstr {
            rd,
            rs1,
            imm,
            len: Width::from(8),
            is_compressed: false,
            is_unsigned: true,
        },
        0b101 => LoadInstr {
            rd,
            rs1,
            imm,
            len: Width::from(16),
            is_compressed: false,
            is_unsigned: true,
        },
        0b110 => LoadInstr {
            rd,
            rs1,
            imm,
            len: Width::from(32),
            is_compressed: false,
            is_unsigned: true,
        },
        0b111 => LoadInstr {
            rd,
            rs1,
            imm,
            len: Width::from(64),
            is_compressed: false,
            is_unsigned: true,
        },
        _ => unreachable!(),
    }
}

fn decode_uncompressed_store(raw: usize) -> StoreInstr {
    let func3 = (raw >> 12) & 0b111;
    let rs1: usize = (raw >> 15) & 0b11111;
    let rs2 = (raw >> 20) & 0b11111;
    let imm = bits_to_int(
        ((raw >> 7) & 0b11111) | ((raw >> 20) & 0b111111100000),
        0,
        11,
    );

    match func3 {
        0b000 => StoreInstr {
            rs2,
            rs1,
            imm,
            len: Width::from(8),
            is_compressed: false,
        },
        0b001 => StoreInstr {
            rs2,
            rs1,
            imm,
            len: Width::from(16),
            is_compressed: false,
        },
        0b010 => StoreInstr {
            rs2,
            rs1,
            imm,
            len: Width::from(32),
            is_compressed: false,
        },
        0b011 => StoreInstr {
            rs2,
            rs1,
            imm,
            len: Width::from(64),
            is_compressed: false,
        },
        _ => unreachable!(),
    }
}

fn decode_register_based_compressed_load(raw: usize) -> LoadInstr {
    let rd = (raw >> 2) & 0b111;
    let rs1 = (raw >> 7) & 0b111;

    // let rd = Register::from(rd + 8);
    // let rs1 = Register::from(rs1 + 8);

    let func3 = (raw >> 13) & 0b111;
    match func3 {
        C_LW => {
            let imm_2 = ((raw >> 6) & 0b1) << 2;
            let imm_5_3 = ((raw >> 10) & 0b111) << 3;
            let imm_6 = ((raw >> 5) & 0b1) << 6;
            LoadInstr {
                rd,
                rs1,
                imm: (imm_6 | imm_5_3 | imm_2) as isize,
                len: Width::from(32),
                is_compressed: true,
                is_unsigned: false,
            }
        }
        C_LD => {
            let imm = (raw >> 7) & 0b111000 | ((raw << 1) & 0b11000000);
            LoadInstr {
                rd,
                rs1,
                imm: imm as isize,
                len: Width::from(64),
                is_compressed: true,
                is_unsigned: false,
            }
        }
        _ => unreachable!(),
    }
}

fn decode_register_based_compressed_store(raw: usize) -> StoreInstr {
    let func3 = (raw >> 13) & 0b111;
    let rs2 = (raw >> 2) & 0b111;
    let rs1 = (raw >> 7) & 0b111;

    // let rs2 = Register::from(rs2 + 8); - Neelu: Why is this needed? 
    // let rs1 = Register::from(rs1 + 8);

    match func3 {
        C_SW => {
            let imm_2 = ((raw >> 6) & 0b1) << 2;
            let imm_5_3 = ((raw >> 10) & 0b111) << 3;
            let imm_6 = ((raw >> 5) & 0b1) << 6;
            StoreInstr {
                rs2,
                rs1,
                imm: (imm_6 | imm_5_3 | imm_2) as isize,
                len: Width::from(32),
                is_compressed: true,
            }
        }
        C_SD => {
            let imm = (raw >> 7) & 0b111000 | ((raw << 1) & 0b11000000);
            StoreInstr {
                rs2,
                rs1,
                imm: imm as isize,
                len: Width::from(64),
                is_compressed: true,
            }
        }
        _ => unreachable!(),
    }
}

/// Extracts the bitwise representation and set to the corresponding signed value
pub fn bits_to_int(raw: usize, start_bit: isize, end_bit: isize) -> isize {
    let mask = (1 << (end_bit - start_bit + 1)) - 1;
    let value = (raw >> start_bit) & mask;

    // Check if the most significant bit is set (indicating a negative value)
    if value & (1 << (end_bit - start_bit)) != 0 {
        // Extend the sign bit to the left
        let sign_extension = !0 << (end_bit - start_bit);
        value as isize | sign_extension
    } else {
        value as isize
    }
}

// When the pMPRV (Modify Privilege) bit is set and a trap occurs, the default behavior in
// _raw_trap_handler is to attempt context storage using address translation.
// However, this approach is incorrect.
//
// To address this issue, we set mtvec to point to this custom trap handler.
// The purpose of this handler is straightforward: it skips the illegal instruction, assuming it is
// 4 bytes wide.
//
// # SAFETY:
//
// The trap handler overwrite the content of the 't5' register (also named 'x30'). When returning,
// t5 is set ot 0 to indicate that a trap occurred.
#[repr(align(4))]
#[naked]
pub extern "C" fn _mprv_trap_handler() {
    unsafe {
        asm!(
            "csrr t5, mepc",
            "addi t5, t5, 4",
            "csrw mepc, t5",
            "li t5, 0",
            "mret",
            options(noreturn)
        );
    }
}