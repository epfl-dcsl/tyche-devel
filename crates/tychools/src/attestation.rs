use std::fs::read_to_string;
use std::path::PathBuf;

use ed25519_compact::{PublicKey, Signature};
use object::elf::{PF_R, PF_W, PF_X};
use object::read::elf::ProgramHeader;
use sha2::{Digest, Sha256};

use crate::elf_modifier::TychePF::PfH;
use crate::elf_modifier::{ModifiedELF, ModifiedSegment, TychePhdrTypes, DENDIAN};

fn hash_acc_rights(hasher: &mut Sha256, flags: u32, mask: u32) {
    if flags & mask != 0 {
        log::trace!("1");
        hasher.input(&u8::to_le_bytes(1 as u8));
    } else {
        log::trace!("0");
        hasher.input(&u8::to_le_bytes(0 as u8));
    }
}

fn hash_segments_info(enclave: &Box<ModifiedELF>, hasher: &mut Sha256, offset: u64) {
    let mut segment_off = offset;
    for seg in &enclave.segments {
        if ModifiedSegment::is_loadable(seg.program_header.p_type(DENDIAN)) {
            if let Some(tpe) = TychePhdrTypes::from_u32(seg.program_header.p_type(DENDIAN)) {
                let start = segment_off;
                let memsz = seg.program_header.p_memsz(DENDIAN);
                let align = seg.program_header.p_align(DENDIAN);
                let sz = (memsz + align - 1) / align * align;
                log::trace!("Region start {:#x}", start);
                log::trace!("Region end {:#x}", start + sz);
                let flags = seg.program_header.p_flags(DENDIAN);
                let mut diff = (memsz + align - 1) / align * align;
                diff = diff - (seg.data.len() as u64);
                log::trace!("Attestation right");
                let should_hash = (flags & (PfH as u32)) != 0;
                log::trace!("{}", should_hash);
                if should_hash {
                    //hashing start - end of segment
                    hasher.input(&u64::to_le_bytes(start));
                    hasher.input(&u64::to_le_bytes(start + sz));
                    //hashing access rights
                    hash_acc_rights(hasher, flags, PfH as u32);
                    log::trace!("X right");
                    hash_acc_rights(hasher, flags, PF_X);
                    log::trace!("W right");
                    hash_acc_rights(hasher, flags, PF_W);
                    log::trace!("R right");
                    hash_acc_rights(hasher, flags, PF_R);
                    //hashing confidential info
                    if tpe.is_confidential() {
                        log::trace!("Conf 1");
                        hasher.input(&u8::to_le_bytes(1 as u8));
                    } else {
                        log::trace!("Conf 0");
                        hasher.input(&u8::to_le_bytes(0 as u8));
                    }
                    //hashing data
                    for u8_data in &seg.data {
                        let arr_u8: [u8; 1] = [*u8_data];
                        hasher.input(&arr_u8);
                    }
                    //padding (allignment) which loader does
                    for _ in 0..diff {
                        let arr_u8: [u8; 1] = [0];
                        hasher.input(&arr_u8);
                    }
                }
                segment_off += sz;
            }
        }
    }
}

pub fn attest(src: &PathBuf, offset: u64, riscv_enabled: bool) -> (u128, u128) {
    let data = std::fs::read(src).expect("Unable to read source file");
    let mut hasher = Sha256::default();
    let mut enclave = ModifiedELF::new(&data);
    enclave.fix_page_tables(offset, riscv_enabled);

    hash_segments_info(&enclave, &mut hasher, offset);

    let result = hasher.result();
    log::info!("Computed hash:");
    log::info!("{}", format!("{:x}", result));
    let hash_low: u128 = u128::from_be_bytes(result.as_slice()[0..16].try_into().unwrap());
    let hash_high: u128 = u128::from_be_bytes(result.as_slice()[16..32].try_into().unwrap());
    (hash_high, hash_low)
}

const MSG_SZ: usize = 32 + 8;
const PB_KEY_SZ: usize = 32;
const ENC_DATA_SZ: usize = 64;
use std::fs::File;
use std::io::Write;

fn copy_arr(dst: &mut [u8], src: &[u8], index: usize) {
    let mut ind = index;
    for x in src {
        dst[ind] = *x;
        ind += 1;
    }
}

pub fn attestation_check(
    src_bin: &PathBuf,
    src_att: &PathBuf,
    offset: u64,
    nonce: u64,
    riscv_enabled: bool,
) {
    log::trace!("Tychools attestation check");
    log::trace!("Binary path {}", src_bin.display());
    log::trace!("Attestation data path {}", src_att.display());
    log::trace!("Offset {:#x}", offset);
    log::trace!("Nonce {:#x}", nonce);
    let mut pub_key_arr: [u8; PB_KEY_SZ] = [0; PB_KEY_SZ];
    let mut enc_data_arr: [u8; ENC_DATA_SZ] = [0; ENC_DATA_SZ];
    let mut index_pub = 0;
    let mut index_enc = 0;
    let mut cnt = 0;
    //read lines from file and make public key and encrypted data
    for line in read_to_string(src_att).unwrap().lines() {
        let num: u32 = line.parse().unwrap();
        if cnt < PB_KEY_SZ {
            pub_key_arr[index_pub] = num as u8;
            index_pub += 1;
        } else {
            enc_data_arr[index_enc] = num as u8;
            index_enc += 1;
        }
        cnt += 1;
    }
    let pkey: PublicKey = PublicKey::new(pub_key_arr);
    let sig: Signature = Signature::new(enc_data_arr);

    let mut message: [u8; MSG_SZ] = [0; MSG_SZ];

    let (hash_high, hash_low) = attest(src_bin, offset, riscv_enabled);
    //fill the bytes of the message to be checked
    copy_arr(&mut message, &u128::to_le_bytes(hash_low), 0);
    copy_arr(&mut message, &u128::to_le_bytes(hash_high), 16);
    copy_arr(&mut message, &u64::to_le_bytes(nonce), 32);
    {
        let mut data_file = File::create("tychools_response.txt").expect("creation failed");
        if let Ok(_r) = pkey.verify(message, &sig) {
            log::info!("Verified!");
            data_file.write(b"Message verified").expect("Write failed");
        } else {
            log::info!("Not verified!");
            data_file
                .write(b"Message was not verified")
                .expect("Write failed");
        }
    }
}
