use self::user_allocator::UserAllocator;
use crate::arch::VirtualAddr;

pub mod page_allocator;
pub mod user_allocator;
pub mod utils;

static mut USER_ALLOCATOR: UserAllocator = UserAllocator::new();

pub fn alloc_user(num_bytes: u64) -> u64 {
    unsafe { USER_ALLOCATOR.malloc(num_bytes).as_u64() }
}

pub fn free_user(addr: VirtualAddr) -> u64 {
    unsafe { USER_ALLOCATOR.free(addr).as_u64() }
}
