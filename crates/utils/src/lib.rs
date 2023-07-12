#![no_std]

mod address;

pub use address::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr, HostVirtAddr};

// ——————————————————————————— Frame Abstraction ———————————————————————————— //

/// Representation of a physical frame.
#[derive(Clone, Copy)]
pub struct Frame {
    /// The physical address of the frame.
    pub phys_addr: HostPhysAddr,

    /// the virtual adddress of the frame using the current mapping.
    ///
    /// WARNING: the mapping must stay stable for the whole duration of VMX operations.
    pub virt_addr: u64,
}

impl Frame {
    /// Creates a new Frames from a physical address and its corresponding virtual address.
    ///
    /// # Safety:
    /// The virtual address must be mapped to the physical address, and the mapping must remain
    /// valid for ever.
    pub unsafe fn new(phys_addr: HostPhysAddr, virt_addr: HostVirtAddr) -> Self {
        let virt_addr = virt_addr.as_usize() as *mut u8 as u64;
        Self {
            phys_addr,
            virt_addr,
        }
    }

    /// Returns a mutable view of the frame.
    pub fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: we assume that the frame address is a valid virtual address exclusively owned by
        // the Frame struct.
        unsafe { core::slice::from_raw_parts_mut(self.virt_addr as *mut u8, 0x1000) }
    }

    pub fn as_ref(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.virt_addr as *mut u8, 0x1000) }
    }

    /// Returns a mutable view of the frame as an array of u64.
    pub fn as_array_page(&mut self) -> &mut [u64] {
        unsafe { core::slice::from_raw_parts_mut(self.virt_addr as *mut u64, 512) }
    }

    /// Zeroes out the frame.
    pub fn zero_out(&mut self) {
        for item in self.as_array_page().iter_mut() {
            *item = 0;
        }
    }

    /// Zeroes out the frame and returns it.
    pub fn zeroed(mut self) -> Self {
        self.zero_out();
        self
    }
}
