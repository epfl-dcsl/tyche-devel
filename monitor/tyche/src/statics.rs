//! # Statically allocated structures
//!
//! We use a `make_manifest` macro to define the manifest used by stage 2. This macros ensures
//! that manifest symbols is properly exposed and can be picked up by stage 1.

use stage_two_abi::make_manifest;

// ————————————————————— Static Resources Configuration ————————————————————— //

pub const NB_PAGES: usize = 200;

// ————————————————————————— Second Stage Manifest —————————————————————————— //

make_manifest!();
