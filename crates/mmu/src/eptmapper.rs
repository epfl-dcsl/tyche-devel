//! EPT mapper implementation

use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::{EptEntryFlags, EptMemoryType};
use vmx::ept::{GIANT_PAGE_SIZE, HUGE_PAGE_SIZE, PAGE_SIZE};

use crate::frame_allocator::FrameAllocator;
use crate::ioptmapper::PAGE_MASK;
use crate::mapper::Mapper;
use crate::walker::{Address, Level, WalkNext, Walker};

pub const ADDRESS_MASK: u64 = 0x7fffffffff000;

pub struct EptMapper {
    host_offset: usize,
    root: HostPhysAddr,
    level: Level,
    //If true, allow use of 1GB, and 2MB mappings. Right now we hardcode this to disabled to support
    //memory partitions. We will re-enable theese mappings later on
    allow_large_mappings: bool,
}

pub const EPT_PRESENT: EptEntryFlags = EptEntryFlags::READ
    .union(EptEntryFlags::WRITE)
    .union(EptEntryFlags::SUPERVISOR_EXECUTE)
    .union(EptEntryFlags::USER_EXECUTE);

/// Flags:
/// 6 << 0; // write-back
/// 3 << 3; // walk length of 4
pub const EPT_ROOT_FLAGS: usize = (6 << 0) | (3 << 3);

unsafe impl Walker for EptMapper {
    type WalkerPhysAddr = HostPhysAddr;
    type WalkerVirtAddr = GuestPhysAddr;

    fn translate(&self, phys_addr: Self::WalkerPhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.host_offset)
    }

    fn root(&mut self) -> (Self::WalkerPhysAddr, Level) {
        (self.root, self.level)
    }

    fn get_phys_addr(entry: u64) -> Self::WalkerPhysAddr {
        Self::WalkerPhysAddr::from_u64(entry & ADDRESS_MASK)
    }
}

impl Mapper for EptMapper {
    fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        addr_in: &impl Address,
        addr_out: &impl Address,
        size: usize,
        prot: u64,
    ) {
        let allow_large = self.allow_large_mappings;
        unsafe {
            self.walk_range(
                GuestPhysAddr::new(addr_in.as_usize()),
                GuestPhysAddr::new(addr_in.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & EPT_PRESENT.bits()) != 0 {
                        if (level == Level::L3 || level == Level::L2)
                            && ((*entry & EptEntryFlags::PAGE.bits()) != 0)
                        {
                            return WalkNext::Leaf;
                        }
                        return WalkNext::Continue;
                    }

                    let end = addr_in.as_usize() + size;
                    let hphys = addr_out.as_usize() + (addr.as_usize() - addr_in.as_usize());
                    if level == Level::L3 {
                        if allow_large
                            && (addr.as_usize() + GIANT_PAGE_SIZE <= end)
                            && (hphys % GIANT_PAGE_SIZE == 0)
                        {
                            *entry = hphys as u64
                                | EptEntryFlags::PAGE.bits()
                                | prot
                                | EptMemoryType::WB.bits()
                                | (1 << 7);
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L2 {
                        if allow_large
                            && (addr.as_usize() + HUGE_PAGE_SIZE <= end)
                            && (hphys % HUGE_PAGE_SIZE == 0)
                        {
                            *entry = hphys as u64
                                | EptEntryFlags::PAGE.bits()
                                | prot
                                | EptMemoryType::WB.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        assert!(hphys % PAGE_SIZE == 0);
                        *entry = hphys as u64 | prot;
                        return WalkNext::Leaf;
                    }
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: unable to allocate page table entry")
                        .zeroed();
                    //*entry = frame.phys_addr.as_u64() | prot.bits();
                    *entry = frame.phys_addr.as_u64() | EPT_PRESENT.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map EPTs");
        }
    }
}

impl EptMapper {
    /// Get HPA for GPA, preserves offset bits
    pub fn lookup(&mut self, gpa: GuestPhysAddr) -> Option<HostPhysAddr> {
        let offset_bits = gpa.as_u64() & PAGE_MASK as u64;
        let mut result_hpa = None;
        let walk_result = unsafe {
            self.walk_range(
                gpa,
                GuestPhysAddr::new(gpa.as_usize() + PAGE_SIZE),
                &mut |_, entry, level| {
                    if (*entry & EPT_PRESENT.bits()) == 0 {
                        return WalkNext::Leaf;
                    }
                    if level == Level::L1 || *entry & EptEntryFlags::PAGE.bits() != 0 {
                        result_hpa = Some(Self::get_hpa(*entry));
                        return WalkNext::Abort;
                    }
                    return WalkNext::Continue;
                },
            )
        };
        //When we find the translation, we abort walk with WalkNext::Abort, this will cause the walker to reutrn an error
        //Thus, we check if we have Some result_hpa to distinguish a failed walk from the deliberate abort
        match (result_hpa, walk_result) {
            //Walk succeeded but GPA is not mapped
            (None, Ok(_)) => return None,
            //Walk succeeded and GPA is mapped
            (Some(hpa), _) => return Some(HostPhysAddr::from_u64(hpa | offset_bits)),
            //Walk failed, mapping status unknown, should not happen if PTs are well formed
            _ => panic!("EPT walk failed"),
        }
    }
    /// Creates a new EPT mapper.
    //#[cfg(not(features = "visionfive2"))]
    pub fn new(host_offset: usize, root: HostPhysAddr) -> Self {
        Self {
            host_offset,
            root,
            level: Level::L4,
            allow_large_mappings: false,
        }
    }
    /*
    #[cfg(features = "visionfive2")]
        pub fn new(host_offset: usize, root: HostPhysAddr) -> Self {
            todo!();
        }
        */

    /// Creates a new EPT mapper that start at the given level.
    pub fn new_at(level: Level, host_offset: usize, root: HostPhysAddr) -> Self {
        Self {
            host_offset,
            root,
            level,
            allow_large_mappings: false,
        }
    }

    fn get_hpa(entry: u64) -> u64 {
        let hfn_mask = 0xFFFFFFFFFF000_u64;
        entry & hfn_mask
    }
    pub fn debug_range(&mut self, gpa: GuestPhysAddr, size: usize) {
        let (phys_addr, _) = self.root();
        log::info!("EPT root: 0x{:x}", phys_addr.as_usize());
        unsafe {
            self.walk_range(
                gpa,
                GuestPhysAddr::new(gpa.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & EPT_PRESENT.bits()) == 0 {
                        return WalkNext::Leaf;
                    }
                    let flags = EptEntryFlags::from_bits_truncate(*entry);
                    log::info!(
                        "{:?} -> 0x{:x} | {:x?} , hpa = 0x{:x}, flags = {:#?}",
                        level,
                        addr.as_usize(),
                        entry,
                        Self::get_hpa(*entry),
                        flags
                    );
                    if (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                        return WalkNext::Leaf;
                    }
                    return WalkNext::Continue;
                },
            )
            .expect("Failed to print the epts");
        }
    }

    /// Scan the PT starting at from `gpa` to `gpa+size` and report the first gpa in that
    /// range that is already mapped to sth. Otherwise return None
    pub fn get_first_used_in_range(
        &mut self,
        gpa: GuestPhysAddr,
        size: usize,
    ) -> Option<(GuestPhysAddr, Level)> {
        let mut found_leaf_in_range = None;
        unsafe {
            self.walk_range(
                gpa,
                GuestPhysAddr::new(gpa.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & EPT_PRESENT.bits()) != 0 {
                        if (level == Level::L3 || level == Level::L2)
                            && ((*entry & EptEntryFlags::PAGE.bits()) != 0)
                        {
                            found_leaf_in_range = Some((addr, level));
                            return WalkNext::Abort;
                        }
                        found_leaf_in_range = Some((addr, level));
                        return WalkNext::Abort;
                    }
                    WalkNext::Continue
                },
            )
            .expect("failed to scan through ept");
        }
        found_leaf_in_range
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
            if (*entry & EPT_PRESENT.bits()) == 0 {
                // No entry
                return WalkNext::Leaf;
            } else if level == Level::L1 || (*entry & EptEntryFlags::PAGE.bits()) != 0 {
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

    pub fn unmap_range(
        &mut self,
        allocator: &impl FrameAllocator,
        gpa: GuestPhysAddr,
        size: usize,
        root: HostPhysAddr,
        offset: usize,
    ) {
        let host_offset = self.host_offset;
        unsafe {
            let mut cleanup = |page_virt_addr: HostVirtAddr| {
                let page_phys = HostPhysAddr::new(page_virt_addr.as_usize() - host_offset);
                allocator
                    .free_frame(page_phys)
                    .expect("failed to free EPT page");
            };
            let mut callback = |addr: GuestPhysAddr, entry: &mut u64, level: Level| {
                if (*entry & EPT_PRESENT.bits()) == 0 {
                    return WalkNext::Leaf;
                }

                let end = gpa.as_usize() + size;
                let mut needs_remap = false;
                let mut big_size: usize = 0;
                let mut aligned_addr = addr.as_usize();

                // We have a big entry
                if level == Level::L3 && (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                    aligned_addr = addr.as_usize() & (level.mask() as usize);
                    // Easy case, the entire entry is to be removed.
                    if gpa.as_usize() <= aligned_addr && (aligned_addr + GIANT_PAGE_SIZE <= end) {
                        *entry = 0;
                        return WalkNext::Leaf;
                    }
                    // Harder case, we need to break the entry.
                    *entry = 0;
                    needs_remap = true;
                    big_size = GIANT_PAGE_SIZE;
                }
                if level == Level::L2 && (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                    aligned_addr = addr.as_usize() & (level.mask() as usize);
                    // Easy case, the entire entry is to be removed.
                    if gpa.as_usize() <= aligned_addr && (aligned_addr + GIANT_PAGE_SIZE <= end) {
                        *entry = 0;
                        return WalkNext::Leaf;
                    }
                    // Harder case, we need to break the entry.
                    *entry = 0;
                    needs_remap = true;
                    big_size = HUGE_PAGE_SIZE;
                }
                if needs_remap {
                    // Harder case for huge entries.
                    let mut mapper = EptMapper::new(offset, root);
                    // Some mapping on the left.
                    if aligned_addr < gpa.as_usize() {
                        let n_size = gpa.as_usize() - aligned_addr;
                        mapper.map_range(
                            allocator,
                            &GuestPhysAddr::new(aligned_addr),
                            &HostPhysAddr::new(aligned_addr),
                            n_size,
                            (EptEntryFlags::READ
                                | EptEntryFlags::WRITE
                                | EptEntryFlags::USER_EXECUTE
                                | EPT_PRESENT)
                                .bits()
                                | EptMemoryType::WB.bits(),
                        );
                    }
                    // Some mapping on the left.
                    if gpa.as_usize() + size < aligned_addr + big_size {
                        let n_size = aligned_addr + big_size - gpa.as_usize() - size;
                        mapper.map_range(
                            allocator,
                            &(gpa + size),
                            &HostPhysAddr::new(gpa.as_usize() + size),
                            n_size,
                            (EptEntryFlags::READ
                                | EptEntryFlags::WRITE
                                | EptEntryFlags::USER_EXECUTE
                                | EPT_PRESENT)
                                .bits()
                                | EptMemoryType::WB.bits(),
                        );
                    }
                    return WalkNext::Leaf;
                }
                if level == Level::L1 {
                    *entry = 0;
                    return WalkNext::Leaf;
                }
                WalkNext::Continue
            };
            self.cleanup_range(
                gpa,
                GuestPhysAddr::new(gpa.as_usize() + size),
                &mut callback,
                &mut cleanup,
            )
            .expect("Failed to unmap EPTs");
        }
    }

    pub fn get_root(&self) -> HostPhysAddr {
        HostPhysAddr::new(self.root.as_usize() | EPT_ROOT_FLAGS)
    }
}

//TODO: ideally, write unit test for our new function. Not sure how to mock the allocator
