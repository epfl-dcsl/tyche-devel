use ed25519_compact::{KeyPair, Noise, PublicKey, SecretKey, Seed, Signature};
pub type DevicePublicKey = PublicKey;
pub type DevicePrivateKey = SecretKey;
pub type AttestationPublicKey = PublicKey;
pub type AttestationPrivateKey = SecretKey;

pub type AttestationSignature = Signature;

pub const MAX_ATTESTATION_DATA_SZ: usize = 8;
pub const ATTESTATION_DATA_SZ: usize = MAX_ATTESTATION_DATA_SZ + 32;

//TPM-added size constants
pub const TPM_ATTESTATION_SZ: usize = 129;
pub const TPM_SIG_SZ: usize = 384;
pub const TPM_MODULUS_SZ: usize = 384;
pub const ATTESTATION_TOTAL_SZ: usize =
    ATTESTATION_DATA_SZ + TPM_ATTESTATION_SZ + TPM_SIG_SZ + TPM_MODULUS_SZ;

//TPM-added types
pub type TpmSignature = [u8; TPM_SIG_SZ];
pub type TpmModulus = [u8; TPM_MODULUS_SZ];
pub type TpmAttestation = [u8; TPM_ATTESTATION_SZ];

//TPM hardcoded signature stuff

pub static mut TPM_ATTESTATION: TpmAttestation = [0; TPM_ATTESTATION_SZ];

pub static mut TPM_SIGNATURE: TpmSignature = [0; TPM_SIG_SZ];

pub static mut TPM_MODULUS: TpmModulus = [0; TPM_MODULUS_SZ];

#[cfg(target_arch = "riscv64")]
#[derive(Copy, Clone, Debug)]
pub struct EnclaveReport {
    pub public_key: PublicKey,                     //32 bytes
    pub signed_enclave_data: AttestationSignature, //64 bytes
    pub tpm_signature: TpmSignature,               //384
    pub tpm_modulus: TpmModulus,                   //384
    pub tpm_attestation: TpmAttestation,           //129
}

#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone, Debug)]
pub struct EnclaveReport {
    pub public_key: PublicKey,
    pub signed_enclave_data: AttestationSignature,
}

pub fn get_attestation_keys() -> (AttestationPublicKey, AttestationPrivateKey) {
    let key_pair = KeyPair::from_seed(Seed::default());
    (key_pair.pk, key_pair.sk)
}

pub fn sign_attestation_data(data: &[u8], key: AttestationPrivateKey) -> AttestationSignature {
    let sig = key.sign(data, Some(Noise::default()));
    sig
}

pub fn sign_by_device(data: &[u8], key: DevicePrivateKey) -> AttestationSignature {
    let sig = key.sign(data, Some(Noise::default()));
    sig
}
