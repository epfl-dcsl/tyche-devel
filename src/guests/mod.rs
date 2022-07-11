pub mod rawc;

pub struct GuestBytes {
    start: u64,
    bytes: &'static [u8],
}
