//! Attestation
//!
//! This module contains the source of the new attestation mechanism, which provides an attestation
//! of the whole system instead of limitting itself to a single trust domain.

use std::fs;

use attest_client::deserialize;

use crate::NewAttestationArgs;

pub fn display(args: &NewAttestationArgs) {
    let file = fs::read(&args.src).expect("Could not open attestation");
    let ctx = deserialize(&file).expect("Failed to deserialize attestation");
    println!("{:?}", ctx);
}
