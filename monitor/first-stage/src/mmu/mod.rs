//! Memory Management unit

pub mod frames;
pub mod scattered_writer;

pub use frames::{get_physical_memory_offset, init, PAGE_SIZE};
