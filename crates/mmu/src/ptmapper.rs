use core::marker::PhantomData;

use bitflags::bitflags;
use utils::HostVirtAddr;

use super::frame_allocator::FrameAllocator;
use super::walker::{Address, Level, WalkNext, Walker};

static PAGE_MASK: usize = !(0x1000 - 1);

pub const ADDRESS_MASK: u64 = 0x7fffffffff000;

pub struct PtMapper<PhysAddr, VirtAddr> {
    /// Offset between host physical memory and virtual memory.
    host_offset: usize,
    /// Offset between host physical and guest physical.
    offset: usize,
    root: PhysAddr,
    _virt: PhantomData<VirtAddr>,
}

bitflags! {
    pub struct PtFlag: u64 {
        const PRESENT = 1 << 0;
        const WRITE = 1 << 1;
        const USER = 1 << 2;
        const PAGE_WRITE_THROUGH = 1 << 3;
        const PAGE_CACHE_DISABLE = 1 << 4;
        const ACCESS = 1 << 5;
        const PSIZE = 1 << 7;
        const HALT = 1 << 11;
        // mark an entry as a pipe.
        const PIPE = 3 << 9;
        const EXEC_DISABLE = 1 << 63;
    }

    pub struct PageSize: usize {
        const GIANT = 1 << 30;
        const HUGE = 1 << 21;
        const NORMAL = 1 << 12;
    }
}

/// Mask to remove the top 12 bits, containing PKU keys and Exec disable bits.
pub const HIGH_BITS_MASK: u64 = !(0b111111111111 << 52);
pub const DEFAULT_PROTS: PtFlag = PtFlag::PRESENT.union(PtFlag::WRITE).union(PtFlag::USER);
pub const MAP_PAGE_TABLE: PtFlag = PtFlag::PRESENT.union(PtFlag::WRITE);

unsafe impl<PhysAddr, VirtAddr> Walker for PtMapper<PhysAddr, VirtAddr>
where
    PhysAddr: Address,
    VirtAddr: Address,
{
    type PhysAddr = PhysAddr;
    type VirtAddr = VirtAddr;

    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.offset + self.host_offset)
    }

    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, Level::L4)
    }

    fn get_phys_addr(entry: u64) -> Self::PhysAddr {
        Self::PhysAddr::from_u64(entry & ADDRESS_MASK)
    }
}

impl<PhysAddr, VirtAddr> PtMapper<PhysAddr, VirtAddr>
where
    PhysAddr: Address,
    VirtAddr: Address,
{
    pub fn new(host_offset: usize, offset: usize, root: PhysAddr) -> Self {
        Self {
            host_offset,
            offset,
            root,
            _virt: PhantomData,
        }
    }

    pub fn translate(&mut self, virt_addr: VirtAddr) -> Option<PhysAddr> {
        // Align the address
        let virt_addr = VirtAddr::from_usize(virt_addr.as_usize() & PAGE_MASK);
        let mut phys_addr = None;
        unsafe {
            self.walk(virt_addr, &mut |entry, level| {
                if *entry & PtFlag::PRESENT.bits() == 0 {
                    // Terminate the walk, no mapping exists
                    return WalkNext::Leaf;
                }
                if level == Level::L1 || *entry & PtFlag::PSIZE.bits() != 0 {
                    let raw_addr = *entry & level.mask() & HIGH_BITS_MASK;
                    let raw_addr_with_offset = raw_addr + (virt_addr.as_u64() & !level.mask());
                    phys_addr = Some(PhysAddr::from_u64(raw_addr_with_offset));
                    // We found an address, terminate the walk.
                    return WalkNext::Leaf;
                }
                // Continue to walk if not yet on a leaf
                return WalkNext::Continue;
            })
            .ok()?;
        }

        phys_addr
    }

    pub fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        size: usize,
        prot: PtFlag,
    ) {
        // Align physical address first
        let phys_addr = PhysAddr::from_usize(phys_addr.as_usize() & PAGE_MASK);
        let offset = self.offset;
        unsafe {
            self.walk_range(
                virt_addr,
                VirtAddr::from_usize(virt_addr.as_usize() + size),
                &mut |addr, entry, level| {
                    // TODO(aghosn) handle rewrite of access rights.
                    if (*entry & PtFlag::PRESENT.bits()) != 0 {
                        *entry = *entry | prot.bits();
                        *entry = *entry & !PtFlag::EXEC_DISABLE.bits();
                        *entry = *entry & !PtFlag::PIPE.bits();
                        return WalkNext::Continue;
                    }

                    let end = virt_addr.as_usize() + size;
                    let phys = phys_addr.as_u64() + (addr.as_u64() - virt_addr.as_u64());
                    // Opportunity to map a 1GB region
                    if level == Level::L3 {
                        if (addr.as_usize() + PageSize::GIANT.bits() <= end)
                            && (phys % (PageSize::GIANT.bits() as u64) == 0)
                        {
                            *entry = phys | PtFlag::PSIZE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    // Opportunity to map a 2MB region.
                    if level == Level::L2 {
                        if (addr.as_usize() + PageSize::HUGE.bits() <= end)
                            && (phys % (PageSize::HUGE.bits() as u64) == 0)
                        {
                            *entry = phys | PtFlag::PSIZE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        assert!(phys % (PageSize::NORMAL.bits() as u64) == 0);
                        *entry = phys | prot.bits();
                        return WalkNext::Leaf;
                    }
                    // Create an entry
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: unable to allocate page table entry.")
                        .zeroed();
                    assert!(frame.phys_addr.as_u64() >= offset as u64);
                    *entry = (frame.phys_addr.as_u64() - (offset as u64)) | DEFAULT_PROTS.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map PTs");
        }
    }

    /// Prints the permissions of page tables for the given range.
    pub fn debug_range(&mut self, virt_addr: VirtAddr, size: usize, dept: Level) {
        unsafe {
            self.walk_range(
                virt_addr,
                VirtAddr::from_usize(virt_addr.as_usize() + size),
                &mut |addr, entry, level| {
                    let flags = PtFlag::from_bits_truncate(*entry);
                    let phys = *entry & ((1 << 63) - 1) & (PAGE_MASK as u64);

                    // Do not go too deep
                    match (dept, level) {
                        (Level::L4, Level::L3)
                        | (Level::L4, Level::L2)
                        | (Level::L4, Level::L1) => return WalkNext::Leaf,
                        (Level::L3, Level::L2) | (Level::L3, Level::L1) => return WalkNext::Leaf,
                        (Level::L2, Level::L1) => return WalkNext::Leaf,
                        _ => (),
                    };

                    // Print if present
                    if flags.contains(PtFlag::PRESENT) {
                        let padding = match level {
                            Level::L4 => "",
                            Level::L3 => "  ",
                            Level::L2 => "    ",
                            Level::L1 => "      ",
                        };
                        log::info!(
                            "{}{:?} Virt: 0x{:x} - Phys: 0x{:x} - {:?}\n",
                            padding,
                            level,
                            addr.as_usize(),
                            phys,
                            flags
                        );
                        WalkNext::Continue
                    } else {
                        WalkNext::Leaf
                    }
                },
            )
            .expect("Failed to print PTs");
        }
    }
}
