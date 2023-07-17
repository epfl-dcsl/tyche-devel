use capa_engine::config::NB_DOMAINS;
use capa_engine::{CapaError, GenArena, Handle};
use mmu::FrameAllocator;
use utils::{Frame, HostPhysAddr};

use crate::allocator::allocator;
use crate::statics::NB_CORES;

/// Simple wrapper for frames representing a frame.
/// This structure will be inside a static array in the monitor.
#[allow(dead_code)]
pub struct RCFrame {
    count: usize,
    pub frame: Frame,
}

impl RCFrame {
    #[allow(dead_code)]
    pub fn new(frame: Frame) -> Self {
        Self { count: 1, frame }
    }
    #[allow(dead_code)]
    pub fn acquire(&mut self) -> usize {
        self.count += 1;
        self.count
    }
    #[allow(dead_code)]
    pub fn release(&mut self) -> Result<usize, CapaError> {
        if self.count == 0 {
            return Err(CapaError::InvalidOperation);
        }

        self.count -= 1;
        Ok(self.count)
    }
}

// ————————————————————— Create a pool for such objects ————————————————————— //

#[allow(dead_code)]
pub type RCFramePool = GenArena<RCFrame, { NB_DOMAINS * NB_CORES }>;

#[allow(dead_code)]
pub fn drop_rc(pool: &mut RCFramePool, v: Handle<RCFrame>) {
    if v.is_invalid() {
        return;
    }
    let count = pool[v].release().expect("Error releasing rcframe");
    if count == 0 {
        let frame = pool[v].frame;
        pool.free(v);
        unsafe {
            allocator()
                .free_frame(frame.phys_addr)
                .expect("Error freeing frame");
        }
    }
}

#[allow(dead_code)]
pub const EMPTY_RCFRAME: RCFrame = RCFrame {
    count: 0,
    frame: Frame {
        phys_addr: HostPhysAddr::new(0),
        virt_addr: 0,
    },
};
