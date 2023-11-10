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

    //#[cfg(not(feature = "visionfive2"))]
    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, Level::L4)
    }

    /* #[cfg(feature = "visionfive2")]
    fn root(&mut self) -> (Self::PhysAddr, Level) {
        todo!();    // Neelu: This is only because we compile all PT mappers to avoid conditional
                    // compilation. So I had to put a proxy here.
    } */

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

    pub fn free_all(mut self, allocator: &impl FrameAllocator) {
        let (root, _) = self.root();
        let host_offset = self.host_offset;
        let mut cleanup = |page_virt_addr: HostVirtAddr| unsafe {
            let page_phys = HostPhysAddr::new(page_virt_addr.as_usize() - host_offset);
            allocator
                .free_frame(page_phys)
                .expect("failed to free EPT page");
        };
        let mut callback = |_: GuestPhysAddr, entry: &mut u64, level: Level| {
            if (*entry & PRESENT.bits()) == 0 {
                // No entry
                return WalkNext::Leaf;
            } else if level == Level::L1 || (*entry & IoPtFlag::PAGE_SIZE.bits()) != 0 {
                // This is a leaf
                return WalkNext::Leaf;
            } else {
                WalkNext::Continue
            }
        };
        unsafe {
            self.cleanup_range(
                GuestPhysAddr::new(0),
                GuestPhysAddr::new(usize::MAX),
                &mut callback,
                &mut cleanup,
            )
            .expect("Failed to free EPTs");
            allocator.free_frame(root).expect("Failed to free root");
        }
    }

    pub fn get_root(&self) -> HostPhysAddr {
        HostPhysAddr::new(self.root.as_usize())
    }
}
