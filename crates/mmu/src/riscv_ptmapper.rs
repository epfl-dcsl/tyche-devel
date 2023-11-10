use core::marker::PhantomData;

use bitflags::bitflags;
use utils::HostVirtAddr;

use super::frame_allocator::FrameAllocator;
use super::walker::{Address, Level, WalkNext, Walker};

static PAGE_MASK: usize = !(0x1000 - 1);

static PAGE_OFFSET_WIDTH: usize = 12;

pub struct RVPtMapper<PhysAddr, VirtAddr> {
    /// Offset between host physical memory and virtual memory.
    host_offset: usize,
    /// Offset between host physical and guest physical.
    offset: usize,
    root: PhysAddr,
    _virt: PhantomData<VirtAddr>, //Neelu: What is this used for?
    level: Level,
}

bitflags! {
    pub struct RVPtFlag: u64 {
        const VALID = 1 << 0;
        const READ = 1 << 1;
        const WRITE = 1 << 2;
        const EXECUTE = 1 << 3;
        const USER = 1 << 4;
        const GLOBAL = 1 << 5;
        const ACCESSED = 1 << 6;
        const DIRTY = 1 << 7;
        const PIPE = 3 << 54;
    }

    pub struct PageSize: usize {
        const GIANT = 1 << 30;
        const HUGE = 1 << 21;
        const NORMAL = 1 << 12;
    }
}

impl RVPtFlag {
    const FLAGS_COUNT: usize = 10;

    pub const fn flags_count() -> usize {
        Self::FLAGS_COUNT
    }
}

/// Mask to remove the top 10 bits, containing N/PBMT/Reserved fields in the PTE.
const DEFAULT_PROTS: RVPtFlag = RVPtFlag::VALID;

unsafe impl<PhysAddr, VirtAddr> Walker for RVPtMapper<PhysAddr, VirtAddr>
where
    PhysAddr: Address,
    VirtAddr: Address,
{
    type PhysAddr = PhysAddr;
    type VirtAddr = VirtAddr;

    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.offset + self.host_offset)
    }

    //#[cfg(not(feature = "visionfive2"))]
    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, self.level)
    }

    /*#[cfg(feature = "visionfive2")]
        fn root(&mut self) -> (Self::PhysAddr, Level) {
            (self.root, Level::L3)
        }
    */

    fn get_phys_addr(entry: u64) -> Self::PhysAddr {
        Self::PhysAddr::from_u64((entry >> RVPtFlag::flags_count()) << PAGE_OFFSET_WIDTH)
    }
}

impl<PhysAddr, VirtAddr> RVPtMapper<PhysAddr, VirtAddr>
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
            level: Level::L4,
        }
    }

    pub fn new_at(host_offset: usize, offset: usize, root: PhysAddr, level: Level) -> Self {
        Self {
            host_offset,
            offset,
            root,
            _virt: PhantomData,
            level,
        }
    }

    pub fn translate(&mut self, virt_addr: VirtAddr) -> Option<PhysAddr> {
        // Align the address
        let virt_addr = VirtAddr::from_usize(virt_addr.as_usize() & PAGE_MASK);
        let mut phys_addr = None;
        unsafe {
            self.walk(virt_addr, &mut |entry, level| {
                if *entry & RVPtFlag::VALID.bits() == 0 {
                    // Terminate the walk, no mapping exists
                    return WalkNext::Leaf;
                }

                if level == Level::L1
                    || *entry & RVPtFlag::READ.bits() != 0
                    || *entry & RVPtFlag::EXECUTE.bits() != 0
                {
                    let raw_addr =
                        ((*entry & level.mask()) >> RVPtFlag::flags_count()) << PAGE_OFFSET_WIDTH;
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
        prot: RVPtFlag,
    ) {
        // Align physical address first
        //log::info!("virt_addr: {:x} phys_addr: {:x} size: {:x}", virt_addr, phys_addr, size);
        let phys_addr = PhysAddr::from_usize(phys_addr.as_usize() & PAGE_MASK);
        let offset = self.offset;
        unsafe {
            self.walk_range(
                virt_addr,
                VirtAddr::from_usize(virt_addr.as_usize() + size),
                &mut |addr, entry, level| {
                    // TODO(aghosn) handle rewrite of access rights.
                    // Neelu: Only updating prots for leaf PTEs.
                    if (*entry & RVPtFlag::VALID.bits()) != 0 {
                        if level == Level::L1 {
                            *entry = *entry | prot.bits();
                            //TODO(neelu): Should prot.bits() be
                            //checked for RWX for non-leaf entries?
                        }
                        return WalkNext::Continue;
                    }

                    let end = virt_addr.as_usize() + size;
                    let phys = phys_addr.as_u64() + (addr.as_u64() - virt_addr.as_u64());

                    // Opportunity to map a 1GB region
                    if level == Level::L3 {
                        if (addr.as_usize() + PageSize::GIANT.bits() <= end)
                            && (phys % (PageSize::GIANT.bits() as u64) == 0)
                        {
                            log::info!("Mapping a 1 GB region");
                            //Make sure protection bits have either read or execute set - to
                            //denote a leaf PTE.
                            *entry = ((phys >> PAGE_OFFSET_WIDTH) << RVPtFlag::flags_count())
                                | prot.bits();
                            assert!(
                                *entry & RVPtFlag::READ.bits() != 0
                                    || *entry & RVPtFlag::EXECUTE.bits() != 0
                            );
                            return WalkNext::Leaf;
                        }
                    }
                    // Opportunity to map a 2MB region.
                    if level == Level::L2 {
                        // log::info!("Mapping a 2 MB region");
                        if (addr.as_usize() + PageSize::HUGE.bits() <= end)
                            && (phys % (PageSize::HUGE.bits() as u64) == 0)
                        {
                            log::info!("Mapping a 2 MB region");
                            *entry = ((phys >> PAGE_OFFSET_WIDTH) << RVPtFlag::flags_count())
                                | prot.bits();
                            assert!(
                                *entry & RVPtFlag::READ.bits() != 0
                                    || *entry & RVPtFlag::EXECUTE.bits() != 0
                            );
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        log::info!("Mapping a normal region");
                        assert!(phys % (PageSize::NORMAL.bits() as u64) == 0);
                        *entry = ((phys >> PAGE_OFFSET_WIDTH) << RVPtFlag::flags_count())
                            | prot.bits()
                            | RVPtFlag::ACCESSED.bits()
                            | RVPtFlag::DIRTY.bits();
                        assert!(
                            *entry & RVPtFlag::READ.bits() != 0
                                || *entry & RVPtFlag::EXECUTE.bits() != 0
                        );
                        return WalkNext::Leaf;
                    }
                    // Create an entry
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: unable to allocate page table entry.")
                        .zeroed();
                    assert!(frame.phys_addr.as_u64() >= offset as u64);
                    *entry = (((frame.phys_addr.as_u64() - (offset as u64)) >> PAGE_OFFSET_WIDTH)
                        << RVPtFlag::flags_count())
                        | DEFAULT_PROTS.bits();
                    assert!(
                        *entry & RVPtFlag::READ.bits() == 0
                            && *entry & RVPtFlag::EXECUTE.bits() == 0
                    );
                    WalkNext::Continue
                },
            )
            .expect("Failed to map PTs");
        }
    }

    //#[cfg(not(feature = "visionfive2"))]
    /// Prints the permissions of page tables for the given range.
    pub fn debug_range(&mut self, virt_addr: VirtAddr, size: usize, dept: Level) {
        unsafe {
            self.walk_range(
                virt_addr,
                VirtAddr::from_usize(virt_addr.as_usize() + size),
                &mut |addr, entry, level| {
                    let flags = RVPtFlag::from_bits_truncate(*entry);
                    let phys = (*entry >> RVPtFlag::flags_count()) << PAGE_OFFSET_WIDTH;

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
                    if flags.contains(RVPtFlag::VALID) {
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
    /*
    #[cfg(feature = "visionfive2")]
        /// Prints the permissions of page tables for the given range.
        pub fn debug_range(&mut self, virt_addr: VirtAddr, size: usize, dept: Level) {
            unsafe {
                self.walk_range(
                    virt_addr,
                    VirtAddr::from_usize(virt_addr.as_usize() + size),
                    &mut |addr, entry, level| {
                        let flags = RVPtFlag::from_bits_truncate(*entry);
                        let phys = (*entry >> RVPtFlag::flags_count()) << PAGE_OFFSET_WIDTH;

                        // Do not go too deep
                        match (dept, level) {
                            (Level::L3, Level::L2) | (Level::L3, Level::L1) => return WalkNext::Leaf,
                            (Level::L2, Level::L1) => return WalkNext::Leaf,
                            _ => (),
                        };

                        // Print if present
                        if flags.contains(RVPtFlag::VALID) {
                            let padding = match level {
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
     */
}
