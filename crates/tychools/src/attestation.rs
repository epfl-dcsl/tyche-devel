use std::fs::read_to_string;
use std::path::PathBuf;

use ed25519_compact::{PublicKey, Signature};
use hex::encode;
use object::elf::{PF_R, PF_W, PF_X};
use object::read::elf::ProgramHeader;
use ring;
use sha2::{Digest, Sha256, Sha384};

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

fn construct_der_rsa_pkey(modulus: &[u8]) -> Vec<u8> {
    let mut der_payload: Vec<u8> = std::vec::Vec::new();
    let mut add_0: u8 = 0;
    if modulus[0] > 127 {
        add_0 = add_0 + 1;
    }
    // DER shenanigans
    //// Sequence tag
    der_payload.push(0x30);
    //// Long form length encoding
    der_payload.push(0x82);
    //// Length bytes (394)
    der_payload.extend([1, (137 + add_0)]);
    //// Modulus object
    //// Integer tag
    der_payload.push(0x02);
    //// Long form length encoding
    der_payload.push(0x82);
    //// Length of 384 bytes (+1 0x0 sometimes)
    der_payload.extend([1, 128 + add_0]);
    //// Modulus data
    //Context-specific byte : if first byte of modulus is >128, add 0x0 byte in front to make it
    //positive.
    if add_0 > 0 {
        der_payload.push(0x0);
    }

    der_payload.extend(modulus);
    //// public exponent object
    der_payload.push(0x02);

    // Short form length
    der_payload.push(0x03);
    // 65537
    der_payload.extend([1, 0, 1]);

    der_payload
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

const TPM_SIG_SZ: usize = 384;
const TPM_ATT_SZ: usize = 129;

const PB_KEY_SZ_1: usize = 31;
const ENC_DATA_SZ_1: usize = 63;
const TPM_SIG_SZ_1: usize = 383;

const TPM_PCR_REDIGEST: &str = "2152d35c16e4f59d3d95e09299c2c73218aec31164d32a000f6e2bc6a0e785fb5c31271dc7fea029e5a9dbebc571129f";
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
    let mut tpm_sig_arr: [u8; TPM_SIG_SZ] = [0; TPM_SIG_SZ];
    let mut tpm_mod_arr: [u8; TPM_SIG_SZ] = [0; TPM_SIG_SZ];
    let mut tpm_att_arr: [u8; TPM_ATT_SZ] = [0; TPM_ATT_SZ];
    let mut tpm_sig_verified: bool = false;
    let mut tpm_pcr_verified: bool = false;
    let mut index_pub = 0;
    let mut index_enc = 0;
    let mut index_sig = 0;
    let mut index_mod = 0;
    let mut index_att = 0;
    let mut cnt = 0;
    //read lines from file and make public key and encrypted data
    for line in read_to_string(src_att).unwrap().lines() {
        let num: u32 = line.parse().unwrap();

        //RISC-V parsing of enclave report (we have DRoT w/ OpenSBI)
        if riscv_enabled {
            match cnt {
                ..=PB_KEY_SZ_1 if index_enc == 0 => {
                    pub_key_arr[index_pub] = num as u8;
                    index_pub += 1;
                }
                ..=ENC_DATA_SZ_1 if index_sig == 0 => {
                    cnt = if index_enc == 0 { cnt - PB_KEY_SZ } else { cnt };
                    enc_data_arr[index_enc] = num as u8;
                    index_enc += 1;
                }
                ..=TPM_SIG_SZ_1 if index_mod == 0 => {
                    cnt = if index_sig == 0 {
                        cnt - ENC_DATA_SZ
                    } else {
                        cnt
                    };
                    tpm_sig_arr[index_sig] = num as u8;
                    index_sig += 1;
                }
                ..=TPM_SIG_SZ if index_att == 0 => {
                    cnt = if index_mod == 0 {
                        cnt - TPM_SIG_SZ
                    } else {
                        cnt
                    };
                    if cnt != TPM_SIG_SZ {
                        tpm_mod_arr[index_mod] = num as u8;
                        index_mod += 1;
                    } else {
                        tpm_att_arr[0] = num as u8;
                    }
                }
                _ if index_att < TPM_ATT_SZ - 1 => {
                    tpm_att_arr[index_att + 1] = num as u8;
                    index_att += 1;
                }
                _ => {}
            }
        //x86 parsing (we don't have TPM support)
        } else {
            if cnt < PB_KEY_SZ {
                pub_key_arr[index_pub] = num as u8;
                index_pub += 1;
            } else {
                enc_data_arr[index_enc] = num as u8;
                index_enc += 1;
            }
        }
        cnt += 1;
    }

    if riscv_enabled {
        log::info!("TPM_PCR_REDIGEST IS : {}", TPM_PCR_REDIGEST);
        log::info!("TPM_PCR_REDIGEST IS : {:?}", encode(&tpm_att_arr[81..]));
        if encode(&(tpm_att_arr[81..])) == TPM_PCR_REDIGEST {
            tpm_pcr_verified = true;
        } else {
            tpm_pcr_verified = false;
        }

        let der_payload = construct_der_rsa_pkey(&tpm_mod_arr);

        let tpm_rsa_pkey = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_3072_8192_SHA384,
            der_payload,
        );

        if let Ok(_t) = tpm_rsa_pkey.verify(&tpm_att_arr, &tpm_sig_arr) {
            tpm_sig_verified = true;
        } else {
            tpm_sig_verified = false;
        }
        let mut tpm_hasher = Sha384::new();
        tpm_hasher.input(&tpm_att_arr);
        let rehash: [u8; 48] = tpm_hasher
            .result()
            .as_slice()
            .try_into()
            .expect("Ain't working that way");
        log::info!("Computed attestation rehash is:");
        log::info!("{}", encode(&rehash));
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
                .write(b"Message was not verified\n")
                .expect("Write failed");
        }
        if riscv_enabled {
            if tpm_pcr_verified {
                log::info!("TPM PCR redigest is verified!");
                data_file
                    .write(b"TPM PCR redigest is verified\n")
                    .expect("Write failed");
            } else {
                log::info!("TPM PCR redigest was not verified!");
                data_file
                    .write(b"TPM PCR redigest was not verified\n")
                    .expect("Write failed");
            }

            if tpm_sig_verified {
                log::info!("TPM signature is verified!");
                data_file
                    .write(b"TPM signature is verified")
                    .expect("Write failed");
            } else {
                log::info!("TPM signature was not verified!\n");
                data_file
                    .write(b"TPM signature  was not verified\n")
                    .expect("Write failed");
            }
        }
    }
}
