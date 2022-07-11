use crate::guests::GuestBytes;

pub const RAWC: GuestBytes = GuestBytes {
    start: 0x1000,
    bytes: include_bytes!("../../guest/rawc"),
};
