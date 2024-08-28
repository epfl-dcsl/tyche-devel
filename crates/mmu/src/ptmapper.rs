use core::cmp::max;
use core::marker::PhantomData;

use bitflags::bitflags;
use utils::HostVirtAddr;
use vmx::ept::PAGE_SIZE;

use super::frame_allocator::FrameAllocator;
use super::walker::{Address, Level, WalkNext, Walker};
use crate::frame_allocator::PhysRange;

static PAGE_MASK: usize = !(0x1000 - 1);

pub const ADDRESS_MASK: u64 = 0x7fffffffff000;

#[derive(Clone)]
pub struct PtMapper<PhysAddr, VirtAddr> {
    /// Offset between host physical memory and virtual memory.
    /// We use this to easily to a "reverse lookup", i.e. phys to virt
    host_offset: usize,
    /// Offset between host physical and guest physical.
    offset: usize,
    root: PhysAddr,
    /// If true, the mapper may use 1GB and 2MB entries when creating new mappings
    /// this assumes that the underlying physical memory is contiguous
    enable_pse: bool,
    _virt: PhantomData<VirtAddr>,
    //keep track of the largest vaddr used by these tables
    highest_used_vaddr: VirtAddr,
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
    type WalkerPhysAddr = PhysAddr;
    type WalkerVirtAddr = VirtAddr;

    fn translate(&self, phys_addr: Self::WalkerPhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.offset + self.host_offset)
    }

    //#[cfg(not(feature = "visionfive2"))]
    fn root(&mut self) -> (Self::WalkerPhysAddr, Level) {
        (self.root, Level::L4)
    }

    /* #[cfg(feature = "visionfive2")]
    fn root(&mut self) -> (Self::PhysAddr, Level) {
        todo!();
    } */

    fn get_phys_addr(entry: u64) -> Self::WalkerPhysAddr {
        Self::WalkerPhysAddr::from_u64(entry & ADDRESS_MASK)
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
            enable_pse: true,
            _virt: PhantomData,
            highest_used_vaddr: VirtAddr::from_u64(0),
        }
    }

    pub fn new_disable_pse(host_offset: usize, offset: usize, root: PhysAddr) -> Self {
        let mut r = Self::new(host_offset, offset, root);
        r.enable_pse = false;
        r
    }

    pub fn get_pt_root(&self) -> PhysAddr {
        self.root
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

    pub fn get_highest_vaddr(&mut self) -> VirtAddr {
        self.highest_used_vaddr
    }

    pub fn get_entry(&mut self, v: VirtAddr) -> Option<PhysAddr> {
        let target_vaddr = v;
        let mut target_paddr: Option<PhysAddr> = None;
        //log::info!("searching ptmapper for 0x{:x}", v.as_u64());
        let walk_result = unsafe {
            self.walk_range(
                target_vaddr,
                VirtAddr::from_usize(target_vaddr.as_usize() + PAGE_SIZE),
                &mut |addr, entry, level| {
                    let flags = PtFlag::from_bits_truncate(*entry);
                    let phys = *entry & ((1 << 63) - 1) & (PAGE_MASK as u64);

                    // Print if present
                    if flags.contains(PtFlag::PRESENT) {
                        /*let padding = match level {
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
                        );*/
                        if addr == target_vaddr && level == Level::L1 {
                            target_paddr = Some(PhysAddr::from_u64(phys));
                            WalkNext::Abort
                        } else {
                            WalkNext::Continue
                        }
                    } else {
                        WalkNext::Leaf
                    }
                },
            )
        };
        match (walk_result, target_paddr) {
            (Ok(_), None) => None,
            (Ok(_), Some(v)) => Some(v),
            (Err(_), None) => panic!("get_entry, page table walk failed"),
            //when we reach the target node, we immediately abort the Pt walk with WalkNext::Abort
            //This will cause the walker to return an error. However, since target_paddr was set to Some
            //we know that we reached target node
            (Err(_), Some(v)) => Some(v),
        }
    }

    /// Convenience wrapper around `map_range` that maps the contiguous virtual address range from
    /// `virt_addr` to `virt_addr+size`, to the physical memory
    /// contained in `phys_ranges`. The start addresses of the physical ranges have to be page aligned
    /// # Return Value
    /// If `phys_ranges` is to small to map `size` bytes, an error is returned, that states the remaining,
    /// unmapped bytes
    pub fn map_range_scattered<T: FrameAllocator>(
        &mut self,
        allocator: &T,
        virt_addr: VirtAddr,
        phys_ranges: &[PhysRange],
        size: usize,
        prot: PtFlag,
    ) -> Result<(), usize> {
        //number of bytes that still need to be mapped
        let mut remaining_bytes = size;
        //log::info!("initial remaining_bytes: 0x{:x}", remaining_bytes);
        let mut next_virt_addr = virt_addr;
        for (_, phys_range) in phys_ranges.iter().enumerate() {
            /*log::info!(
                "{:2} processing phys_range {:x?}",
                phys_range_idx,
                phys_range
            );*/
            assert_eq!(phys_range.start.as_usize() % PAGE_SIZE, 0);
            let phys_addr = PhysAddr::from_usize(phys_range.start.as_usize());

            //compute number of bytes that we can map in this iteration
            let mapping_size = if remaining_bytes > phys_range.size() {
                phys_range.size()
            } else {
                remaining_bytes
            };

            /* We disable pse here to prevent usage of 1GB and 2MB mappings, as the current
             * implementation of this feature assumes all remaining bytes to be physicallay contiguous
             * which might not be the case for our phys range. Could be optimized later on, by adjusting
             * based on phys range size.
             */
            /*log::info!("map_range_scattered: calling map_range with vaddr 0x{:x}, paddr 0x{:x}, size 0x{:x}",
            next_virt_addr.as_u64(), phys_addr.as_u64(), mapping_size);*/
            self.enable_pse = false;
            self.map_range(allocator, next_virt_addr, phys_addr, mapping_size, prot);
            self.enable_pse = true;
            remaining_bytes -= mapping_size;

            //log::info!("new remaining_bytes: 0x{:x}", remaining_bytes);
            if remaining_bytes == 0 {
                return Ok(());
            }

            next_virt_addr = next_virt_addr
                .add(mapping_size as u64)
                .expect("virt addr overflow");
        }
        if remaining_bytes > 0 {
            Err(remaining_bytes)
        } else {
            Ok(())
        }
    }

    /// Creates mapping from `virt_addr`` to `phys_addr`, assuming physically contiguous memory
    /// See `map_range_scattered` if you want to map scattered physical memory pages
    pub fn map_range<T: FrameAllocator>(
        &mut self,
        allocator: &T,
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        size: usize,
        prot: PtFlag,
    ) {
        // Align physical address first
        let phys_addr = PhysAddr::from_usize(phys_addr.as_usize() & PAGE_MASK);
        // this is supposed to handle host phys to guest phys, in stage1 ctx this is always 0
        let offset = self.offset;
        let enable_pse = self.enable_pse;
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

                    let end: usize = virt_addr.as_usize() + size;
                    //luca: this is the phys addr to to which the pte will point
                    //here we make use of the identity mapping assumption in the address calucation
                    let phys = phys_addr.as_u64() + (addr.as_u64() - virt_addr.as_u64());
                    // Opportunity to map a 1GB region
                    if level == Level::L3 {
                        if enable_pse
                            && (addr.as_usize() + PageSize::GIANT.bits() <= end)
                            && (phys % (PageSize::GIANT.bits() as u64) == 0)
                        {
                            *entry = phys | PtFlag::PSIZE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    // Opportunity to map a 2MB region.
                    if level == Level::L2 {
                        if enable_pse
                            && (addr.as_usize() + PageSize::HUGE.bits() <= end)
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
            self.highest_used_vaddr = VirtAddr::from_usize(max(
                self.highest_used_vaddr.as_usize(),
                virt_addr.as_usize() + size,
            ));
        }
    }

    #[cfg(not(feature = "visionfive2"))]
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
