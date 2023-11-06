use bitflags::bitflags;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};

use crate::frame_allocator::FrameAllocator;
use crate::walker::{Address, Level, WalkNext, Walker};

pub const ADDRESS_MASK: u64 = 0x7fffffffff000;

pub struct IoPtMapper {
    host_offset: usize,
    root: HostPhysAddr,
}

bitflags! {
    pub struct IoPtFlag: u64 {
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const EXECUTE   = 1 << 2;
        const PAGE_SIZE = 1 << 7;
        const ACCESSED  = 1 << 8;
        const DIRTY     = 1 << 9;
        const SNOOP     = 1 << 11;
    }
}

pub const HUGE_PAGE_SIZE: usize = 1 << 21;
pub const PAGE_SIZE: usize = 1 << 12;

pub const DEFAULT_PROTS: IoPtFlag = IoPtFlag::READ
    .union(IoPtFlag::WRITE)
    .union(IoPtFlag::EXECUTE);
pub const PRESENT: IoPtFlag = IoPtFlag::READ
    .union(IoPtFlag::WRITE)
    .union(IoPtFlag::EXECUTE);

unsafe impl Walker for IoPtMapper {
    type PhysAddr = HostPhysAddr;
    type VirtAddr = GuestPhysAddr;

    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.host_offset)
    }

    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, Level::L4)
    }

    fn get_phys_addr(entry: u64) -> Self::PhysAddr {
        Self::PhysAddr::from_u64(entry & ADDRESS_MASK)
    }
}

impl IoPtMapper {
    pub fn new(host_offset: usize, root: HostPhysAddr) -> Self {
        Self { host_offset, root }
    }

    pub fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        size: usize,
        prot: IoPtFlag,
    ) {
        unsafe {
            self.walk_range(
                gpa,
                GuestPhysAddr::new(gpa.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & PRESENT.bits()) != 0 {
                        return WalkNext::Continue;
                    }

                    let end = gpa.as_usize() + size;
                    let hphys = hpa.as_usize() + (addr.as_usize() - gpa.as_usize());

                    if level == Level::L2 {
                        if (addr.as_usize() + HUGE_PAGE_SIZE <= end)
                            && (hphys % HUGE_PAGE_SIZE == 0)
                        {
                            *entry = hphys as u64 | IoPtFlag::PAGE_SIZE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        assert!(hphys % PAGE_SIZE == 0);
                        *entry = hphys as u64 | prot.bits();
                        return WalkNext::Leaf;
                    }
                    // Create an entry
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: unable to allocate page table entry.")
                        .zeroed();
                    *entry = frame.phys_addr.as_u64() | DEFAULT_PROTS.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map I/O PTs");
        }
    }

    pub fn get_root(&self) -> HostPhysAddr {
        HostPhysAddr::new(self.root.as_usize())
    }
}
