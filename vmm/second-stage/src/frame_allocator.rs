//! Linked list allocator
//! Inpired from allocator.rs from aghosn_stage2 branch and https://os.phil-opp.com/allocator-designs/

// TODO check for safe static operations

use vmx::{Frame, HostPhysAddr};

const PAGE_SIZE: u64 = 0x1000;
const NB_PAGES: usize = 40;

#[derive(Copy, Clone)]
#[repr(C, align(0x1000))]
pub struct Page {
    pub data: [u8; PAGE_SIZE as usize],
}

pub struct PageInfo {
    pub frame_id: usize,
    pub next_free: Option<&'static mut PageInfo>,
}

static mut MEMORY_PAGES: [Page; NB_PAGES] = [Page {
    data: [0; PAGE_SIZE as usize],
}; NB_PAGES];

// Linked list stored as an array
static mut LINKED_LIST_FREE_PAGES: [PageInfo; NB_PAGES] = std::mem::uninitialized(); // TODO: DEPRECATED

pub struct FrameAllocator {
    head: Option<&'static mut PageInfo>,
    phys_offset: u64,
    virt_offset: u64,
}

impl FrameAllocator {
    pub fn new(phys: u64, virt: u64) -> Self {
        Self::init();
        Self {
            head: Some(&mut LINKED_LIST_FREE_PAGES[0]),
            phys_offset: phys,
            virt_offset: virt,
        }
    }

    pub fn init() {
        for i in 0..NB_PAGES - 1 {
            LINKED_LIST_FREE_PAGES[i] = PageInfo {
                frame_id: i,
                next_free: Some(&mut LINKED_LIST_FREE_PAGES[i + 1]),
            }
        }
        LINKED_LIST_FREE_PAGES[NB_PAGES - 1] = PageInfo {
            frame_id: NB_PAGES - 1,
            next_free: None,
        }
    }

    fn allocate_frame_get_id(&self) -> Option<usize> {
        let curr_head = self.head;
        match curr_head {
            Some(x) => {
                self.head = x.next_free; // Move head to the next free page
                Some(x.frame_id)
            }
            None => None,
        }
    }

    pub fn allocate_frame(&mut self) -> Option<Frame> {
        let id = Self::allocate_frame_get_id(&mut self);
        match id {
            Some(x) => {
                let addr = &MEMORY_PAGES[x] as *const _ as *mut u8;
                let phys_addr = (addr as u64) - self.virt_offset + self.phys_offset;
                return Some(Frame {
                    phys_addr: HostPhysAddr::new(phys_addr as usize),
                    virt_addr: addr,
                });
            }
            None => None,
        }
    }

    pub fn deallocate_frame(&mut self, frame: Frame) {
        let id = frame.virt_addr - &MEMORY_PAGES[0];
        if 0 < id || id <= NB_PAGES { // Simply return if index is out of bounds
            return;
        }

        // Replace the head with the new freed frame
        let old_head = self.head;
        // TODO: how to put back the new free block in the linked list? For now I use
        // the fact that we have a 1 1 mapping between MEMORY_PAGES and LINKED_LIST_FREE_PAGES.
        self.head = Some(&mut LINKED_LIST_FREE_PAGES[id]);
        LINKED_LIST_FREE_PAGES[id].next_free = old_head;
    }
}
