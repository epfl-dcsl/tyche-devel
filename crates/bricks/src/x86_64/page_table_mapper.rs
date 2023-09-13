use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::VirtAddr;

use super::VirtualAddr;

pub type PageAccess = usize;
pub const USER_ACCESS: PageAccess = 0;
pub const KERNEL_ACCESS: PageAccess = 1;
const NUM_LEVELS: usize = 4;
const VIRT_PAGE_ADDR: u64 = 0x0800000000000;

pub fn change_access(addr_virt: &VirtualAddr, access: PageAccess) {
    let (page_table_root, _) = Cr3::read();
    let addr = addr_virt.addr;
    let phys_start = page_table_root.start_address().as_u64();
    let table_indexes = [
        addr.p4_index(),
        addr.p3_index(),
        addr.p2_index(),
        addr.p1_index(),
    ];
    let mut frame = page_table_root;
    for i in 0..NUM_LEVELS {
        let index = table_indexes[i];
        let virt =
            VirtAddr::new((VIRT_PAGE_ADDR as u64) + (frame.start_address().as_u64() - phys_start));
        let table_ptr: *mut PageTable = virt.as_mut_ptr();
        let table = unsafe { &mut *table_ptr };
        let entry = &mut table[index];
        if i == NUM_LEVELS - 1 {
            match access {
                USER_ACCESS => {
                    entry.set_flags(PageTableFlags::union(
                        entry.flags(),
                        PageTableFlags::USER_ACCESSIBLE,
                    ));
                }
                KERNEL_ACCESS => {
                    PageTableFlags::remove(&mut entry.flags(), PageTableFlags::USER_ACCESSIBLE)
                }
                _ => x86_64::instructions::hlt(),
            }
        } else {
            frame = match entry.frame() {
                Ok(frame) => frame,
                _ => {
                    panic!("Frame should always be ok");
                }
            };
        }
    }
}
