use crate::allocator::page_allocator::bricks_setup_allocator;
use crate::arch::transition::setup_rsp;
use crate::shared_buffer::{bricks_debug, BRICKS_SHARED_BUFFER, BRICKS_SHARED_BUFFER_SIZE};

// Introduced by tychools
pub const BRICKS_INFO_SEGMENT: usize = BRICKS_SHARED_BUFFER + BRICKS_SHARED_BUFFER_SIZE;

// TODO if there is something that is not u64, conversion will not work
#[derive(Copy, Clone)]
pub struct BricksData {
    memory_pool_start: u64,
    memory_pool_size: u64,
    user_stack_start: u64,
}

pub fn get_tychools_info() {
    unsafe {
        let bricks_data: BricksData = *(BRICKS_INFO_SEGMENT as *mut BricksData);
        bricks_debug(bricks_data.memory_pool_start);
        bricks_debug(bricks_data.memory_pool_size);
        bricks_debug(bricks_data.user_stack_start);
        bricks_setup_allocator(bricks_data.memory_pool_start, bricks_data.memory_pool_size);
        setup_rsp(bricks_data.user_stack_start);
    }
}
