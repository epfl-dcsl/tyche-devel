use bitflags::bitflags;
use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};

use crate::frame_allocator::FrameAllocator;
use crate::mapper::Mapper;
use crate::walker::{Address, Level, WalkNext, Walker};

pub const ADDRESS_MASK: u64 = 0x7fffffffff000;

pub struct IoPtMapper {
    host_offset: usize,
    root: HostPhysAddr,
    allow_large: bool,
}

//See Table 39 in vtd spec
bitflags! {
    pub struct IoPtFlag: u64 {
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const EXECUTE   = 1 << 2;
        ///If 1, this is a leaf that points to 4KiB page
        const PAGE_SIZE = 1 << 7;
        const ACCESSED  = 1 << 8;
        const DIRTY     = 1 << 9;
        const SNOOP     = 1 << 11;
    }
}

pub const HUGE_PAGE_SIZE: usize = 1 << 21;
pub const PAGE_SHIFT: usize = 12;
pub const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
pub const PAGE_MASK: usize = PAGE_SIZE - 1;

pub const DEFAULT_PROTS: IoPtFlag = IoPtFlag::READ
    .union(IoPtFlag::WRITE)
    .union(IoPtFlag::EXECUTE);
pub const PRESENT: IoPtFlag = IoPtFlag::READ
    .union(IoPtFlag::WRITE)
    .union(IoPtFlag::EXECUTE);

unsafe impl Walker for IoPtMapper {
    type WalkerPhysAddr = HostPhysAddr;
    type WalkerVirtAddr = GuestPhysAddr;

    fn translate(&self, phys_addr: Self::WalkerPhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.host_offset)
    }

    //#[cfg(not(feature = "visionfive2"))]
    fn root(&mut self) -> (Self::WalkerPhysAddr, Level) {
        (self.root, Level::L4)
    }

    /* #[cfg(feature = "visionfive2")]
    fn root(&mut self) -> (Self::PhysAddr, Level) {
        todo!();    // Neelu: This is only because we compile all PT mappers to avoid conditional
                    // compilation. So I had to put a proxy here.
    } */

    fn get_phys_addr(entry: u64) -> Self::WalkerPhysAddr {
        Self::WalkerPhysAddr::from_u64(entry & ADDRESS_MASK)
    }
}
//TODO: change the trait so that the address types are preserved (e.g. GuestPhys)
impl Mapper for IoPtMapper {
    fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        addr_in: &impl Address,  //guest phys
        addr_out: &impl Address, //host phys
        size: usize,
        prot: u64,
    ) {
        let allow_large = self.allow_large;
        unsafe {
            self.walk_range(
                GuestPhysAddr::new(addr_in.as_usize()),
                GuestPhysAddr::new(addr_in.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & PRESENT.bits()) != 0 {
                        return WalkNext::Continue;
                    }

                    let end = addr_in.as_usize() + size;
                    let hphys = addr_out.as_usize() + (addr.as_usize() - addr_in.as_usize());

                    if level == Level::L2 {
                        if allow_large
                            && (addr.as_usize() + HUGE_PAGE_SIZE <= end)
                            && (hphys % HUGE_PAGE_SIZE == 0)
                        {
                            *entry = hphys as u64 | IoPtFlag::PAGE_SIZE.bits() | prot;
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        assert!(hphys % PAGE_SIZE == 0);
                        *entry = hphys as u64 | prot;
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
}

impl IoPtMapper {
    pub fn new(host_offset: usize, root: HostPhysAddr) -> Self {
        Self {
            host_offset,
            root,
            allow_large: false,
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

    pub fn debug_range(&mut self, gpa: GuestPhysAddr, size: usize) {
        let (phys_addr, _) = self.root();
        log::info!("EPT root: 0x{:x}", phys_addr.as_usize());
        unsafe {
            self.walk_range(
                gpa,
                GuestPhysAddr::new(gpa.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & PRESENT.bits()) == 0 {
                        return WalkNext::Leaf;
                    }
                    let flags = IoPtFlag::from_bits_truncate(*entry);
                    log::info!(
                        "{:?} -> 0x{:x} | {:x?} , hpa = 0x{:x}, flags = {:#?}",
                        level,
                        addr.as_usize(),
                        entry,
                        *entry & 0x0_03f_fff_fff_fff_000, //ignore upper 8 bits and lower 12 bits.
                        flags
                    );
                    if (*entry & IoPtFlag::PAGE_SIZE.bits()) != 0 {
                        return WalkNext::Leaf;
                    }
                    return WalkNext::Continue;
                },
            )
            .expect("Failed to print the epts");
        }
    }
}
