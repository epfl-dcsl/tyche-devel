///This mapper does not require the GPAs to be identity mapped
/// to the stage1 memory. Instead it explictly stores 
/// the HPA for each GPA. To achieve this, we hackily reuse the
/// existing ptmapper as a "dictionary"
use core::cell::RefCell;
use core::marker::PhantomData;

use vmx::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr};

use crate::frame_allocator::PhysRange;
use crate::ioptmapper::PAGE_SIZE;
use crate::ptmapper::{PageSize, DEFAULT_PROTS};
use crate::walker::{Address, Level, WalkNext, Walker};
use crate::{PtFlag, PtMapper, RangeAllocator};
static PAGE_MASK: usize = !(0x1000 - 1);

pub struct GPAToHVATranslator {}

pub const ADDRESS_MASK: u64 = 0x7fffffffff000;

/*
This struct is intended to construct a GVA -> GPA page table, while operating in stage1 with a virt to phys identity mapping
The tricky part is , that we need to store GPAs in the intermediate leafs of our page table structure but also need
to be able to traverse and modify our page tabe while we are in stage1. I.e. we need the HVAs for the GPAs
 */
pub struct GuestPtMapper<GuestPhysAddr, GuestVirtAddr> {
    root: GuestPhysAddr,
    _virt: PhantomData<GuestVirtAddr>,
    //in our pt, we store GVA -> GPA. When traversing our PT, we need to get the HVA for the GPA
    //because we construct the PT's while in the host address space. We use this mapper to get this kind of translation
    //TODO: test if we can directly use HVA here as target addr
    gpa_hpa_tables: RefCell<PtMapper<HostPhysAddr, GuestPhysAddr>>,
    //allow huge and large mappings
    enable_pse: bool,
}

//luca: to my understanding this trait is used when we traverse our page table
unsafe impl Walker for GuestPtMapper<GuestPhysAddr, GuestVirtAddr> {
    type WalkerPhysAddr = GuestPhysAddr;
    type WalkerVirtAddr = GuestVirtAddr;

    //this is used when we traverse our page table to translate the "physical" addresses that we have stored inside our
    //page table into virtual addresses that we can access in the current context
    fn translate(&self, phys_addr: Self::WalkerPhysAddr) -> vmx::HostVirtAddr {
        let paddr = match self.gpa_hpa_tables.borrow_mut().get_entry(phys_addr) {
            Some(host_phys) => {
                //vmx::HostVirtAddr::new(self.gpa_hpa_tables.borrow().translate(host_phys).as_usize())
                host_phys
            }
            None => {
                log::error!(
                    "guest_ptmapper: failed to lookup GPA {:x?} in inner GPA->HPA table. Our GPA for our PT root is {:x?}",
                    phys_addr,self.get_pt_root_gpa()
                );
                panic!("unexpected page table construction error");
            }
        };
        /*log::info!(
            "GuestPtmapper Walker: translated GPA 0x{:x} to HPA 0x{:x}",
            phys_addr.as_u64(),
            paddr.as_u64()
        );*/
        self.gpa_hpa_tables.borrow().translate(paddr)
    }

    fn root(&mut self) -> (Self::WalkerPhysAddr, crate::walker::Level) {
        (self.root, Level::L4)
    }

    fn get_phys_addr(entry: u64) -> Self::WalkerPhysAddr {
        Self::WalkerPhysAddr::from_u64(entry & ADDRESS_MASK)
    }
}

impl GuestPtMapper<GuestPhysAddr, GuestVirtAddr> {
    pub fn new(root: GuestPhysAddr, gpa_hpa_tables: PtMapper<HostPhysAddr, GuestPhysAddr>) -> Self {
        Self {
            root,
            _virt: PhantomData,
            gpa_hpa_tables: RefCell::new(gpa_hpa_tables),
            enable_pse: false,
        }
    }

    pub fn get_pt_root_gpa(&self) -> GuestPhysAddr {
        self.root
    }

    /// Convenience wrapper around `map_range` that maps the contiguous virtual address range from
    /// `virt_addr` to `virt_addr+size`, to the physical memory
    /// contained in `phys_ranges`. The start addresses of the physical ranges have to be page aligned
    /// # Return Value
    /// If `phys_ranges` is to small to map `size` bytes, an error is returned, that states the remaining,
    /// unmapped bytes
    pub fn map_range_scattered<T: RangeAllocator>(
        &mut self,
        allocator: &T,
        virt_addr: GuestVirtAddr,
        phys_ranges: &[PhysRange],
        size: usize,
        prot: PtFlag,
    ) -> Result<(), usize> {
        //number of bytes that still need to be mapped
        let mut remaining_bytes = size;
        let mut next_virt_addr = virt_addr;
        for (_, phys_range) in phys_ranges.iter().enumerate() {
            assert_eq!(phys_range.start.as_usize() % PAGE_SIZE, 0);

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
            self.enable_pse = false;
            self.map_range(allocator, next_virt_addr, GuestPhysAddr::new(next_virt_addr.as_usize()), mapping_size, prot);
            self.enable_pse = true;
            remaining_bytes -= mapping_size;

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
    pub fn map_range<T: RangeAllocator>(
        &mut self,
        allocator: &T,
        virt_addr: GuestVirtAddr,
        phys_addr: GuestPhysAddr,
        size: usize,
        prot: PtFlag,
    ) {
        // Align physical address first
        let phys_addr = phys_addr.align_down(PAGE_SIZE);
        // this is supposed to handle host phys to guest phys, in stage1 ctx this is always 0
        let enable_pse = self.enable_pse;

        //TODO: hacky. Data is not actually cloned, i.e. still same page table structure.
        //We are a bit constrained here be the way the traits are defined. I think this should move into a separate
        //state object that we pass to this function
        let mut gpa_to_hpa_tables = self.gpa_hpa_tables.get_mut().clone();

        unsafe {
            self.walk_range(
                virt_addr,
                GuestVirtAddr::from_usize(virt_addr.as_usize() + size),
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
                    let frame_gpa = allocator.gpa_of_next_allocation();
                    let frame = allocator
                        .allocate_frame()
                        .expect("map_range: unable to allocate page table entry.")
                        .zeroed();

                    /*store the HPA of the frame that we just allocated
                    *when traversing our page table itself, we need to map the gpa to and hpa (and then to and hva)
                    in order to do the traversal itself. To do this, we query the `gpa_to_hpa_tables` that we update here
                    */
                    gpa_to_hpa_tables.map_range(
                        allocator,
                        frame_gpa,
                        frame.phys_addr,
                        PAGE_SIZE,
                        DEFAULT_PROTS,
                    );

                    *entry = frame_gpa.as_u64() | DEFAULT_PROTS.bits();
                    WalkNext::Continue
                },
            )
            .expect("Failed to map PTs");
        }
    }

    #[cfg(not(feature = "visionfive2"))]
    /// Prints the permissions of page tables for the given range.
    pub fn debug_range(&mut self, virt_addr: GuestVirtAddr, size: usize, dept: Level) {
        //TODO: hacky. Data is not actually cloned, i.e. still same page table structure.
        //We are a bit constrained here be the way the traits are defined. I think this should move into a separate
        //state object that we pass to this function
        let mut gpa_to_hpa_tables = self.gpa_hpa_tables.get_mut().clone();
        unsafe {
            self.walk_range(
                virt_addr,
                GuestVirtAddr::from_usize(virt_addr.as_usize() + size),
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
                       
                            if level == Level::L1 {
                                log::info!(
                                    "{}{:?} Virt: 0x{:x} - Phys: 0x{:x} - {:?}\n",
                                    padding,
                                    level,
                                    addr.as_usize(),
                                    phys,
                                    flags);
                            } else {
                                let spa = match gpa_to_hpa_tables
                                .get_entry(GuestPhysAddr::new(phys as usize))
                                {
                                    Some(spa) => spa,
                                    None => {
                                        log::error!("GuestPtmapper::debug_range : At Level {:?}, failed to look up SPA for GPA 0x{:x}",
                                    level,phys);
                                    panic!("unexpected pt walk error");
                                    },
                                };
                                log::info!(
                                    "{}{:?} Virt: 0x{:x} - Phys: 0x{:x} - {:?} ; SPA 0x{:x}\n",
                                    padding,
                                    level,
                                    addr.as_usize(),
                                    phys,
                                    flags,
                                    spa.as_u64(),);
                            }
                       
                        
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
