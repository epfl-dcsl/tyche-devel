use x86_64::VirtAddr;

use self::bricks_allocator::{BricksAllocator, NUM_PAGES};
use self::user_allocator::UserAllocator;
// TODO implement trait for VirtualAddr
pub mod bricks_allocator;
pub mod page_allocator;
pub mod user_allocator;

static mut BRICKS_ALLOCATOR: BricksAllocator = BricksAllocator {
    pages: [0; NUM_PAGES],
    allocated: [false; NUM_PAGES],
};

static mut USER_ALLOCATOR: UserAllocator = UserAllocator {
    pages: [0; NUM_PAGES],
    allocated: [false; NUM_PAGES],
};

pub fn alloc_user(num_bytes: u64) -> (bool, VirtAddr) {
    unsafe { USER_ALLOCATOR.malloc(num_bytes) }
}

pub fn alloc_bricks(num_bytes: u64) -> (bool, VirtAddr) {
    unsafe { BRICKS_ALLOCATOR.kmalloc(num_bytes) }
}

pub fn free_user(addr: VirtAddr) -> bool {
    unsafe { USER_ALLOCATOR.free(addr) }
}

pub fn free_bricks(addr: VirtAddr) -> bool {
    unsafe { BRICKS_ALLOCATOR.kfree(addr) }
}
