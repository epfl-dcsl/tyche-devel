use core::arch::asm;

pub fn local_sfence_vma() {
    unsafe { 
        asm!("sfence.vma");
    }
}

//Corresponding to func_id 1 for EXT_RFENCE
//pub fn local_sfence_vma_range() {
//
//}

//Corresponding to func_id 2 for EXT_RFENCE
pub fn local_sfence_vma_asid(start: usize, size: usize, asid: usize) {

    if start == 0 && size == 0 {
        local_sfence_vma();
    } else { 
        //if size > MAX_TLB_FLUSH_RANGE_SIZE {
        //Todo: For now flushing the entire context for the asid - this can be changed to be more
        //fine grained. 
        unsafe {
            asm!("sfence.vma x0, {}", in(reg)asid);
        }
    }

}
