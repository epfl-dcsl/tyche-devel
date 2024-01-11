//! Intel VT-d driver

#![no_std]

use core::arch::x86_64;
use core::{ptr, slice};

use bitflags::bitflags;
use mmu::FrameAllocator;
use vmx::{HostPhysAddr, HostVirtAddr};

/// Command bits that have an effect when set to 1 (e.g. update internal I/O MMU state).
const ONE_SHOOT_COMMAND_BITS: Command = Command::SET_ROOT_PTR
    .union(Command::WRITE_FLUSH_BUFFER)
    .union(Command::SET_INT_REMAP_PTR);

/// A device identifier, in the form bus:device.function (BDF).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct DeviceId {
    bus: u8,
    dev_fun: u8,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct RootEntry {
    pub entry: u64,
    pub reserved: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ContextEntry {
    pub lower: u64,
    pub upper: u64,
}

// ———————————————————————————————— I/O MMU ————————————————————————————————— //

/// An helper for accessing I/O MMU configuration.
pub struct Iommu {
    addr: *mut u8,
}

macro_rules! ro_reg {
    ($t:ty, $addr:expr, $get:ident) => {
        pub fn $get(&self) -> $t {
            unsafe { ptr::read_volatile(self.addr.offset($addr) as *mut $t) }
        }
    };

    ($t:ty, $addr:expr, $get:ident, $bitflag:ident) => {
        pub fn $get(&self) -> $bitflag {
            unsafe {
                let raw = ptr::read_volatile(self.addr.offset($addr) as *mut $t);
                $bitflag::from_bits_unchecked(raw)
            }
        }
    };
}

macro_rules! wo_reg {
    ($t:ty, $addr:expr, $set:ident) => {
        pub fn $set(&mut self, val: $t) {
            unsafe { ptr::write_volatile(self.addr.offset($addr) as *mut $t, val) }
        }
    };
}

macro_rules! rw_reg {
    ($t:ty, $addr:expr, $get:ident, $set:ident) => {
        ro_reg!($t, $addr, $get);
        wo_reg!($t, $addr, $set);
    };

    ($t:ty, $addr:expr, $get:ident, $set:ident, $bitflag:ident) => {
        ro_reg!($t, $addr, $get, $bitflag);
        wo_reg!($t, $addr, $set);
    };
}

impl Iommu {
    pub const unsafe fn new(addr: HostVirtAddr) -> Self {
        Self {
            addr: addr.as_usize() as *mut u8,
        }
    }

    pub fn set_addr(&mut self, addr: usize) {
        self.addr = addr as *mut u8;
    }

    pub fn update_root_table_addr(&mut self) {
        self.execute_oneshoot_command(Command::SET_ROOT_PTR);
    }

    pub fn enable_translation(&mut self) {
        self.execute_toggle_command(Command::TRANSLATION_ENABLE, true);
    }

    pub fn iter_fault(&mut self) -> FaultIterator {
        let capability = self.get_capability().bits();
        let fault_reg_offset = ((capability >> 24) & 0b1111111111) * 16;
        let fault_reg_start = unsafe {
            let iommu_start = self.addr as *mut u8;
            iommu_start.offset(fault_reg_offset as isize)
        };
        let nb_regs = ((capability >> 40) & 0b11111111) + 1;

        let fault_status = self.get_fault_status();
        let fault_idx = if fault_status.contains(FaultStatus::PRIMARY_PENDING_FAULT) {
            (fault_status.bits() >> 8) & 0b11111111
        } else {
            0
        };

        FaultIterator {
            fault_reg_start,
            nb_regs: nb_regs as usize,
            idx: fault_idx as usize,
            iommu: self,
        }
    }

    /// Executes a one-shot command (e.g. reloading the root table pointer).
    fn execute_oneshoot_command(&mut self, cmd: Command) {
        let status = self.get_global_status() & !ONE_SHOOT_COMMAND_BITS;
        let new_status = status | cmd;

        self.set_global_command(new_status.bits());
        self.wait_on_global_status(cmd, true);
    }

    /// Executes a command that toggle a setting (e.g. enable/disable translation).
    fn execute_toggle_command(&mut self, cmd: Command, enable: bool) {
        let status = self.get_global_status();
        let new_status = if enable {
            status & !ONE_SHOOT_COMMAND_BITS | cmd
        } else {
            status & !ONE_SHOOT_COMMAND_BITS & !cmd
        };

        self.set_global_command(new_status.bits());
        self.wait_on_global_status(cmd, enable);
    }

    /// Spinloops until the global status is updated with the given command, indicating the the
    /// command was processed.
    fn wait_on_global_status(&self, cmd: Command, set: bool) {
        loop {
            let status = self.get_global_status();
            if set & status.contains(cmd) {
                return;
            } else if !set & !status.intersects(cmd) {
                return;
            }

            // Tell the CPU that we are in a spinloop
            unsafe { x86_64::_mm_pause() };
        }
    }

    ro_reg!(u32, 0x000, get_version);
    ro_reg!(u64, 0x008, get_capability, Capability);
    ro_reg!(u64, 0x010, get_extended_capability, ExtendedCapability);
    wo_reg!(u32, 0x018, set_global_command);
    ro_reg!(u32, 0x01C, get_global_status, Command);
    rw_reg!(u64, 0x020, get_root_table_addr, set_root_table_addr);
    rw_reg!(u64, 0x028, get_context_command, set_context_command);
    rw_reg!(u32, 0x034, get_fault_status, set_fault_status, FaultStatus);
    rw_reg!(u32, 0x038, get_fault_event_control, set_fault_event_control);
    rw_reg!(u32, 0x03C, get_fault_event_data, set_fault_event_data);
    rw_reg!(u32, 0x040, get_fault_event_addr, set_fault_event_addr);
    rw_reg!(
        u32,
        0x044,
        get_fault_event_upper_addr,
        set_fault_event_upper_addr
    );
    // TODO: u128, fault recording register
    rw_reg!(
        u32,
        0x064,
        get_protect_memory_enable,
        set_protect_memory_enable
    );
    rw_reg!(
        u32,
        0x068,
        get_protect_low_memory_base,
        set_protect_low_memory_base
    );
    rw_reg!(
        u32,
        0x06C,
        get_protect_low_memory_limit,
        set_protect_low_memory_limit
    );
    rw_reg!(
        u64,
        0x070,
        get_protect_high_memory_base,
        set_protect_high_memory_base
    );
    rw_reg!(
        u64,
        0x078,
        get_protect_high_memory_limit,
        set_protect_high_memory_limit
    );
    rw_reg!(
        u64,
        0x0B8,
        get_interrupt_remapping_table_addr,
        set_interrupt_remapping_table_addr
    );
    ro_reg!(u64, 0x100, get_mttr_capability);
}

// ————————————————————————————— Fault Iterator ————————————————————————————— //

#[derive(Debug)]
pub struct FaultInfo {
    pub addr: u64,
    pub record: FaultRecording,
}

pub struct FaultIterator<'iommu> {
    /// Start of the fault recording registers.
    fault_reg_start: *mut u8,
    /// Number of fault registers.
    nb_regs: usize,
    /// Index of the next fault.
    idx: usize,
    /// Keep track of iommu lifetime to avoid race conditions
    iommu: &'iommu mut Iommu,
}

unsafe impl Send for Iommu {}

impl<'iommu> Iterator for FaultIterator<'iommu> {
    type Item = FaultInfo;

    fn next(&mut self) -> Option<Self::Item> {
        let (low, high) = unsafe {
            let ptr_low = self.fault_reg_start.offset((self.idx * 16) as isize) as *mut u64;
            let ptr_high = ptr_low.offset(1);

            let low = ptr::read_volatile(ptr_low);
            let high = FaultRecording::from_bits_unchecked(ptr::read_volatile(ptr_high));

            if high.contains(FaultRecording::FAULT) {
                // Clear fault bit, this is done by writing 1 to the bit.
                ptr::write_volatile(ptr_high, high.bits());
            } else {
                // Clean overflow bit
                self.iommu
                    .set_fault_status(self.iommu.get_fault_status().bits());
                return None;
            }

            (low, high)
        };

        // Increment index
        self.idx += 1;
        if self.idx >= self.nb_regs {
            self.idx = 0;
        }

        Some(FaultInfo {
            addr: low,
            record: high,
        })
    }
}

pub fn setup_iommu_context(
    iopt_root: HostPhysAddr,
    allocator: &impl FrameAllocator,
) -> HostPhysAddr {
    let ctx_frame = allocator
        .allocate_frame()
        .expect("I/O MMU context frame")
        .zeroed();
    let root_frame = allocator
        .allocate_frame()
        .expect("I/O MMU root frame")
        .zeroed();
    let ctx_entry = ContextEntry {
        upper: 0b010, // 4 lvl pages
        lower: iopt_root.as_u64() | 0b0001,
    };
    let root_entry = RootEntry {
        reserved: 0,
        entry: ctx_frame.phys_addr.as_u64() | 0b1, // Mark as present
    };

    unsafe {
        let ctx_array = slice::from_raw_parts_mut(ctx_frame.virt_addr as *mut ContextEntry, 256);
        let root_array = slice::from_raw_parts_mut(root_frame.virt_addr as *mut RootEntry, 256);

        for entry in ctx_array {
            *entry = ctx_entry;
        }
        for entry in root_array {
            *entry = root_entry;
        }
    }

    root_frame.phys_addr
}

// ————————————————————————————————— Flags —————————————————————————————————— //

bitflags! {
    pub struct Capability: u64 {
        /// Number of domains supported
        const NB_DOMAINS              = 0b111;
        /// Require write buffer flushing.
        const WRITE_BUFFER_FLUSH      = 1 << 4;
        const PROTECTED_LOW_MEMORY    = 1 << 5;
        const PROTECTED_HIGH_MEMORY   = 1 << 6;
        const CACHING_MODE            = 1 << 7;
        const PT_39_BITS              = 1 << 9;
        const PT_48_BITS              = 1 << 10;
        const PT_57_BITS              = 1 << 11;
        const MAXIMUM_GUEST_WIDTH     = 0b111111 << 16;
        const ZERO_LENGTH_READ        = 1 << 22;
        const FAULT_RECORDING_REG     = 0b1111111111 << 24;
        const SECOND_STAGE_2MB        = 1 << 34;
        const SECOND_STAGE_1GB        = 1 << 35;
        const PAGE_SELECTIVE_INVAL    = 1 << 39;
        const NB_FAULT_RECORDING_REG  = 0b11111111 << 40;
        const MAX_ADDR_MASK_VALUE     = 0b111111 << 48;
        const WRITE_DRAINING          = 1 << 54;
        const READ_DRAINING           = 1 << 55;
        const F_STAGE_1GB             = 1 << 56;
        const POSTED_INTERRUPT        = 1 << 59;
        const F_STAGE_5LVL            = 1 << 60;
        const ENHANCED_CMD_SUPPORT    = 1 << 61;
        const ENHANCED_SET8INT_REMAP  = 1 << 62;
        const ENHANCED_SET8ROOT_TABLE = 1 << 63;
    }

    pub struct ExtendedCapability: u64 {
        const PAGE_WALK_COHERENCY       = 1 << 0;
        const QUEUED_INVALIDATION       = 1 << 1;
        const DEVICE_TLB_SUPPORT        = 1 << 2;
        const INT_REMAP_SUPPORT         = 1 << 3;
        const EXTENDED_INT_MODE         = 1 << 4;
        const PASS_THROUGH              = 1 << 6;
        const SNOOP_CONTROL             = 1 << 7;
        const IOTLB_REG_OFFSET          = 0b1111111111 << 8;
        const MAX_HANDLE_MASK_VAL       = 0b1111 << 20;
        const MEMORY_TYPE_SUPPORT       = 1 << 25;
        const NESTED_TRANSLATION        = 1 << 26;
        const PAGE_REQUEST              = 1 << 29;
        const EXECUTE_REQUEST           = 1 << 30;
        const SUPERVISOR_REQUEST        = 1 << 31;
        const NO_WRITE_FLAG             = 1 << 33;
        const EXTENDED_ACCESS_FLAG      = 1 << 34;
        const PROCESS_ASID_SIZE         = 0b11111 << 35;
        const PROCESS_ASID              = 1 << 40;
        const DEVICE_TLB_INVAL_THROTTLE = 1 << 41;
        const PAGE_REQUEST_DRAIN        = 1 << 42;
        const SCALABLE_MODE_SUPPORT     = 1 << 43;
        const VIRTUAL_CMD_SUPPORT       = 1 << 44;
        const S_STAGE_ACCESS_DIRTY      = 1 << 45;
        const S_STAHE_TRANSLATION       = 1 << 46;
        const SCALABLE_MODE_COHERENCY   = 1 << 48;
        const RID_PASID                 = 1 << 49;
        const PERF_MONITORING           = 1 << 51;
        const ABORT_DMA_MODE            = 1 << 52;
        const RID_PRIV                  = 1 << 53;
        const STOP_MARKER_SUPPORT       = 1 << 58;
    }

    pub struct Command: u32 {
        const COMPATIBILITY_FORMAT_INT = 1 << 23;
        const SET_INT_REMAP_PTR        = 1 << 24;
        const INT_REMAP_ENABLE         = 1 << 25;
        const QUEUED_INVALIDATION      = 1 << 26;
        const WRITE_FLUSH_BUFFER       = 1 << 27;
        const SET_ROOT_PTR             = 1 << 30;
        const TRANSLATION_ENABLE       = 1 << 31;
    }

    pub struct FaultStatus: u32 {
        const PRIMARY_FAULT_OVERFLOW        = 1 << 0;
        const PRIMARY_PENDING_FAULT         = 1 << 1;
        const INVALIDATION_QUEUE_ERROR      = 1 << 4;
        const INVALIDATION_COMPLETION_ERROR = 1 << 5;
        const INVALIDATION_TIME_OUT_ERROR   = 1 << 6;
        const FAULT_RECORD_INDEX            = 0b11111111 << 8;
    }

    pub struct FaultRecording: u64 {
        const SOURCE_ID           = 0b111111111111111;
        const T2                  = 1 << 28;
        const PRIVILEGE_MODE_REQ  = 1 << 29;
        const EXEC_ACCESS_REQUEST = 1 << 30;
        const PASID_PRESENT       = 1 << 31;
        const FAULT_RESON         = 0b11111111 << 32;
        const PASID               = 0b11111111111111111111 << 40;
        const ADDRESS_TYPE        = 0b11 << 60;
        const T1                  = 1 << 62;
        const FAULT               = 1 << 63;
    }
}

impl FaultRecording {
    pub fn reason(self) -> u8 {
        ((self.bits() >> 32) & 0b11111111) as u8
    }
}
