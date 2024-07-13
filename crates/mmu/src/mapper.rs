use crate::{walker::Address, FrameAllocator};

pub trait Mapper {
    fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        addr_in: &impl Address,
        addr_out: &impl Address,
        size: usize,
        prot: u64);
}