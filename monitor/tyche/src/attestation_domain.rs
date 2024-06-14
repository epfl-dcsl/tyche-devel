#![allow(unused_imports)]
use attestation::hashing::{self, TycheHasher};
use attestation::signature::{
    self, get_attestation_keys, EnclaveReport, ATTESTATION_DATA_SZ, TPM_ATTESTATION, TPM_MODULUS,
    TPM_SIGNATURE,
};
use capa_engine::{CapaEngine, CapaInfo, Domain, Handle, MemOps, NextCapaToken};
use spin::MutexGuard;

// —————————————————————— Initial measurement —————————————————————— //

fn hash_access_right(hasher: &mut TycheHasher, access_rights: u8, mask: u8) {
    if access_rights & mask != 0 {
        hashing::hash_segment(hasher, &u8::to_le_bytes(1 as u8));
    } else {
        hashing::hash_segment(hasher, &u8::to_le_bytes(0 as u8));
    }
}

fn hash_capa_info(
    hasher: &mut TycheHasher,
    engine: &mut MutexGuard<'_, CapaEngine>,
    domain: Handle<Domain>,
) {
    let mut next_capa = NextCapaToken::new();
    while let Some((info, next_next_capa)) = engine.enumerate(domain, next_capa) {
        next_capa = next_next_capa;
        match info {
            CapaInfo::Region {
                start,
                end,
                unique,
                children: _,
                ops,
            } => {
                if ops.contains(MemOps::HASH) {
                    // Hashing start - end of region
                    hashing::hash_segment(hasher, &(usize::to_le_bytes(start)));
                    hashing::hash_segment(hasher, &(usize::to_le_bytes(end)));

                    // Hashing access rights
                    let access_rights = ops.bits();
                    hash_access_right(hasher, access_rights, MemOps::HASH.bits());
                    hash_access_right(hasher, access_rights, MemOps::EXEC.bits());
                    hash_access_right(hasher, access_rights, MemOps::WRITE.bits());
                    hash_access_right(hasher, access_rights, MemOps::READ.bits());

                    // Hash conf/shared info
                    let conf_info = if unique { 1 as u8 } else { 0 as u8 };
                    hashing::hash_segment(hasher, &(u8::to_le_bytes(conf_info)));

                    // Hashing region data info
                    let mut addr = start;
                    let addr_end = end;
                    while addr < addr_end {
                        unsafe {
                            let byte_data = *(addr as *const u8);
                            let byte_arr: [u8; 1] = [byte_data as u8];
                            hashing::hash_segment(hasher, &byte_arr);
                            addr = addr + 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn calculate_attestation_hash(engine: &mut MutexGuard<'_, CapaEngine>, domain: Handle<Domain>) {
    let mut hasher = hashing::get_hasher();

    hash_capa_info(&mut hasher, engine, domain);

    log::info!("Finished calculating the hash!");

    engine.set_hash(domain, hashing::get_hash(&mut hasher));
}

// —————————————————————— Attestation —————————————————————— //

fn copy_array(dst: &mut [u8], src: &[u8], index: usize) {
    let mut ind_help = index;
    for x in src {
        dst[ind_help] = *x;
        ind_help += 1;
    }
}

#[cfg(target_arch = "riscv64")]
pub fn attest_domain(
    engine: &mut MutexGuard<CapaEngine>,
    current: Handle<Domain>,
    nonce: usize,
    mode: usize,
) -> Option<EnclaveReport> {
    if mode == 0 {
        let enc_hash = engine[current].get_hash();
        let mut sign_data: [u8; ATTESTATION_DATA_SZ] = [0; ATTESTATION_DATA_SZ];
        enc_hash.to_byte_arr(&mut sign_data, 0);
        copy_array(&mut sign_data, &usize::to_le_bytes(nonce), 32);
        let (pb_key, priv_key) = get_attestation_keys();
        let signed_enc_data = signature::sign_attestation_data(&sign_data, priv_key);
        unsafe {
            let rep = EnclaveReport {
                public_key: pb_key,
                signed_enclave_data: signed_enc_data,
                tpm_signature: TPM_SIGNATURE,
                tpm_modulus: TPM_MODULUS,
                tpm_attestation: TPM_ATTESTATION,
            };
            engine.set_report(current, rep);
            Some(rep)
        }
    } else {
        engine[current].get_report()
    }
}

#[cfg(target_arch = "x86_64")]
pub fn attest_domain(
    engine: &mut MutexGuard<CapaEngine>,
    current: Handle<Domain>,
    nonce: usize,
    mode: usize,
) -> Option<EnclaveReport> {
    if mode == 0 {
        let enc_hash = engine[current].get_hash();
        let mut sign_data: [u8; ATTESTATION_DATA_SZ] = [0; ATTESTATION_DATA_SZ];
        enc_hash.to_byte_arr(&mut sign_data, 0);
        copy_array(&mut sign_data, &usize::to_le_bytes(nonce), 32);
        let (pb_key, priv_key) = get_attestation_keys();
        let signed_enc_data = signature::sign_attestation_data(&sign_data, priv_key);
        let rep = EnclaveReport {
            public_key: pb_key,
            signed_enclave_data: signed_enc_data,
        };
        engine.set_report(current, rep);
        Some(rep)
    } else if mode == 1 {
        engine[current].get_report()
    } else {
        log::trace!("Wrong mode");
        None
    }
}
