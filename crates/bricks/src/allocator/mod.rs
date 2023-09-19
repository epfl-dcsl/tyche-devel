use self::bricks_allocator::BricksAllocator;
use self::user_allocator::UserAllocator;
use crate::arch::VirtualAddr;

pub mod bricks_allocator;
pub mod page_allocator;
pub mod user_allocator;
pub mod utils;

static mut BRICKS_ALLOCATOR: BricksAllocator = BricksAllocator::new();

static mut USER_ALLOCATOR: UserAllocator = UserAllocator::new();

pub fn alloc_user(num_bytes: u64) -> u64 {
    unsafe { USER_ALLOCATOR.malloc(num_bytes).as_u64() }
}

pub fn alloc_bricks(num_bytes: u64) -> (bool, VirtualAddr) {
    unsafe { BRICKS_ALLOCATOR.kmalloc(num_bytes) }
}

pub fn free_user(addr: VirtualAddr) -> u64 {
    unsafe { USER_ALLOCATOR.free(addr).as_u64() }
}

pub fn free_bricks(addr: VirtualAddr) -> bool {
    unsafe { BRICKS_ALLOCATOR.kfree(addr) }
}
