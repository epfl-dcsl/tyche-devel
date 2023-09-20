use self::user_allocator::UserAllocator;
use crate::arch::VirtualAddr;

pub mod page_allocator;
pub mod user_allocator;
pub mod utils;

static mut USER_ALLOCATOR: UserAllocator = UserAllocator::new();

pub fn sbrk_user(num_bytes: u64) -> u64 {
    // SAFETY: unsafe because of static mut
    // otherwise it is safe to use it this way because we have only single thread
    // our memory layout is not designed for multiple threads for now
    unsafe { USER_ALLOCATOR.sbrk(num_bytes).as_u64() }
}

pub fn brk_user(addr: VirtualAddr) -> u64 {
    // SAFETY: unsafe because of static mut
    // otherwise it is safe to use it this way because we have only single thread
    // our memory layout is not designed for multiple threads for now
    unsafe { USER_ALLOCATOR.brk(addr).as_u64() }
}
