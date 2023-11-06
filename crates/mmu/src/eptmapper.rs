//! EPT mapper implementation

use utils::{GuestPhysAddr, HostPhysAddr, HostVirtAddr};
use vmx::bitmaps::EptEntryFlags;
use vmx::ept::{GIANT_PAGE_SIZE, HUGE_PAGE_SIZE, PAGE_SIZE};

use crate::frame_allocator::FrameAllocator;
use crate::walker::{Address, Level, WalkNext, Walker};

pub const ADDRESS_MASK: u64 = 0x7fffffffff000;

pub struct EptMapper {
    host_offset: usize,
    root: HostPhysAddr,
    level: Level,
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
    type PhysAddr = HostPhysAddr;
    type VirtAddr = GuestPhysAddr;

    fn translate(&self, phys_addr: Self::PhysAddr) -> HostVirtAddr {
        HostVirtAddr::new(phys_addr.as_usize() + self.host_offset)
    }

    fn root(&mut self) -> (Self::PhysAddr, Level) {
        (self.root, self.level)
    }

    fn get_phys_addr(entry: u64) -> Self::PhysAddr {
        Self::PhysAddr::from_u64(entry & ADDRESS_MASK)
    }
}

impl EptMapper {
    /// Creates a new EPT mapper.
    pub fn new(host_offset: usize, root: HostPhysAddr) -> Self {
        Self {
            host_offset,
            root,
            level: Level::L4,
        }
    }

    /// Creates a new EPT mapper that start at the given level.
    pub fn new_at(level: Level, host_offset: usize, root: HostPhysAddr) -> Self {
        Self {
            host_offset,
            root,
            level,
        }
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
                    log::info!("{:?} -> 0x{:x} | {:x?}", level, addr.as_usize(), entry);
                    if (*entry & EptEntryFlags::PAGE.bits()) != 0 {
                        return WalkNext::Leaf;
                    }
                    return WalkNext::Continue;
                },
            )
            .expect("Failed to print the epts");
        }
    }

    /// Maps a range of physical memory to the given virtual memory.
    pub fn map_range(
        &mut self,
        allocator: &impl FrameAllocator,
        gpa: GuestPhysAddr,
        hpa: HostPhysAddr,
        size: usize,
        prot: EptEntryFlags,
    ) {
        unsafe {
            self.walk_range(
                gpa,
                GuestPhysAddr::new(gpa.as_usize() + size),
                &mut |addr, entry, level| {
                    if (*entry & EPT_PRESENT.bits()) != 0 {
                        if (level == Level::L3 || level == Level::L2)
                            && ((*entry & EptEntryFlags::PAGE.bits()) != 0)
                        {
                            return WalkNext::Leaf;
                        }
                        return WalkNext::Continue;
                    }

                    let end = gpa.as_usize() + size;
                    let hphys = hpa.as_usize() + (addr.as_usize() - gpa.as_usize());
                    if level == Level::L3 {
                        if (addr.as_usize() + GIANT_PAGE_SIZE <= end)
                            && (hphys % GIANT_PAGE_SIZE == 0)
                        {
                            *entry = hphys as u64 | EptEntryFlags::PAGE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L2 {
                        if (addr.as_usize() + HUGE_PAGE_SIZE <= end)
                            && (hphys % HUGE_PAGE_SIZE == 0)
                        {
                            *entry = hphys as u64 | EptEntryFlags::PAGE.bits() | prot.bits();
                            return WalkNext::Leaf;
                        }
                    }
                    if level == Level::L1 {
                        assert!(hphys % PAGE_SIZE == 0);
                        *entry = hphys as u64 | prot.bits();
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
                            GuestPhysAddr::new(aligned_addr),
                            HostPhysAddr::new(aligned_addr),
                            n_size,
                            EptEntryFlags::READ
                                | EptEntryFlags::WRITE
                                | EptEntryFlags::USER_EXECUTE
                                | EPT_PRESENT,
                        );
                    }
                    // Some mapping on the left.
                    if gpa.as_usize() + size < aligned_addr + big_size {
                        let n_size = aligned_addr + big_size - gpa.as_usize() - size;
                        mapper.map_range(
                            allocator,
                            gpa + size,
                            HostPhysAddr::new(gpa.as_usize() + size),
                            n_size,
                            EptEntryFlags::READ
                                | EptEntryFlags::WRITE
                                | EptEntryFlags::USER_EXECUTE
                                | EPT_PRESENT,
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
