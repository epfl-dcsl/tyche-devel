pub const PUB_KEY_SIZE: usize = 32;
pub const SIGNED_DATA_SIZE: usize = 64;
pub const CALC_REPORT: usize = 0;
pub const READ_REPORT: usize = 1;

#[derive(Copy, Clone)]
pub struct AttestationResult {
    pub pub_key: [u8; PUB_KEY_SIZE],
    pub signed_enclave_data: [u8; SIGNED_DATA_SIZE],
}

impl Default for AttestationResult {
    fn default() -> Self {
        AttestationResult {
            pub_key: [0; PUB_KEY_SIZE],
            signed_enclave_data: [0; SIGNED_DATA_SIZE],
        }
    }
}
