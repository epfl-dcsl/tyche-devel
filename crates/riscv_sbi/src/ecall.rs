use core::arch::asm;
use core::sync::atomic::Ordering;
use riscv_utils::{read_mscratch, RegisterState, HART_START, HART_START_ADDR, HART_START_ARG1}; 

use crate::ipi::aclint_mswi_send_ipi;

use crate::{sbi, TYCHE_SBI_VERSION, sbi_ext_base, sbi_ext_hsm};

pub fn ecall_handler(mut ret: &mut isize, mut err: &mut usize, mut out_val: &mut usize, reg_state: RegisterState) {
    //println!("ecall handler a7: {:x}",a7);
    match reg_state.a7 {
        sbi::EXT_BASE => sbi_ext_base_handler(&mut ret, &mut err, &mut out_val, reg_state.a0.try_into().unwrap(), reg_state.a6),
        sbi::EXT_HSM => sbi_ext_hsm_handler(&mut ret, &mut err, &mut out_val, reg_state.a0.try_into().unwrap(), reg_state.a1.try_into().unwrap(), reg_state.a2, reg_state.a6),
        _ => ecall_handler_failed(),
    }
}

// ------------------------------- SBI BASE CALL HANDLER and HELPERS ----------------------- //
pub fn sbi_ext_base_handler(ret: &mut isize, _err: &mut usize, out_val: &mut usize, a0: usize, a6: usize) {
    //let mut a6: usize;
    //unsafe { asm!("mv {}, a6", out(reg) a6); }
    //println!("base_handler a6: {:x}",a6);
    *ret = 0;
    match a6 {
        sbi_ext_base::GET_SPEC_VERSION => *out_val = get_sbi_spec_version(),
        sbi_ext_base::GET_IMP_ID => *out_val = sbi::ECALL_IMPID,
        sbi_ext_base::GET_IMP_VERSION => *out_val = TYCHE_SBI_VERSION,
        sbi_ext_base::GET_MVENDORID | sbi_ext_base::GET_MARCHID | sbi_ext_base::GET_MIMPID => {
            *out_val = get_m_x_id(a6)
        }
        sbi_ext_base::PROBE_EXT => (*ret, *out_val) = probe(a0, a6),
        _ => ecall_handler_failed(),
    }
}

pub fn sbi_ext_hsm_handler(ret: &mut isize, _err: &mut usize, out_val: &mut usize, a0: usize, a1: usize, a2: usize, a6: usize) {
    //Todo: Need to support various HSM extension calls - for now just processing hart start 
    if a0 > 3 {
        log::info!("Invalid hart id!");
        return;
    }

    match a6 {
        sbi_ext_hsm::HART_START => {
            log::info!("SBI_HSM_HART_START!");
            //unsafe { asm!("csrsi mip, 2"); }
            //a0: hartid, a1: start_addr, a2: arg1
            HART_START_ADDR[a0].store(a1, Ordering::SeqCst);    
            HART_START_ARG1[a0].store(a2, Ordering::SeqCst); 
            HART_START[a0].store(true, Ordering::SeqCst);
            aclint_mswi_send_ipi(a0);
        } 
        _ => ecall_handler_failed(),
    }
} 

pub fn get_sbi_spec_version() -> usize {
    let mut spec_ver: usize;

    spec_ver = (sbi::ECALL_VERSION_MAJOR << sbi::SPEC_VERSION_MAJOR_OFFSET)
        & (sbi::SPEC_VERSION_MAJOR_MASK << sbi::SPEC_VERSION_MAJOR_OFFSET);
    spec_ver |= sbi::ECALL_VERSION_MINOR;
    //println!("Computed spec_version: {:x}",spec_ver);
    return spec_ver;
}

pub fn probe(a0: usize, a6: usize) -> (isize, usize) {
    //println!("probing a0 {:x}",a0);
    let mut ret: isize = 0;
    let mut out_val: usize = 0; 

    match a0 {
        sbi::EXT_HSM => {
            match a6 {
                sbi_ext_hsm::HART_SUSPEND => {
                    log::info!("Hart_suspend");
                    ret = 0;
                    out_val=1;
                    //sbi_hsm_hart_suspend();
                }
                sbi_ext_hsm::HART_START | sbi_ext_hsm::HART_STOP | sbi_ext_hsm::HART_GET_STATUS => {
                    log::info!("Hart start/stop/status");
                    ret = 0; 
                    out_val = 0;
                }
                _ => ecall_handler_failed(),
            }
        }
        sbi::EXT_TIME | sbi::EXT_IPI | sbi::EXT_RFENCE=> {
            ret = 0;
            out_val = 1;
            log::info!("PROBING sbi::EXT_TIME/IPI/RFENCE.")
        }
        //Handlers for the corresponding ecall are not yet implemented.
        //sbi::EXT_RFENCE => {
        //    ret = 1;
        //    log::info!("PROBING sbi::EXT_RFENCE")
        //}
        sbi::EXT_SRST => out_val = sbi_ext_srst_probe(a0),
        _ => ecall_handler_failed(),
    }

    //println!("Returning from probe {}",ret);

    return (ret, out_val);
}

/* pub fn sbi_hsm_hart_suspend() -> usize {
    //let mut ret: usize = 0; 
    //let mut oldstate: usize = 0;

    //let hart_scratch: &mut sbi_scratch = read_mscratch();
    

    
    //Todo: Sanity check on domain assigned to current hart - suspends are only allowed from U-mode/S-mode. 
    //Currently, we don't track "domain" as used in openSBI in Tyche. (See openSBI boot log domain
    //info). This is orthogonal to Tyche's "domains". 
    
    //Todo: Sanity check on suspend type 
    //--- 

        //Todo: More sanity checks - non-retentive suspend 
        //

    //Todo: Save next_addr, next_mode, priv 
    
    //sbi_scratch offset ptr - scratch is nothing but mscratch register value - which typically
    //should point to the scratch memory of that hart.
    
} */

pub fn get_m_x_id(a6: usize) -> usize {
    let mut ret: usize = 0;
    match a6 {
        sbi_ext_base::GET_MVENDORID => unsafe {
            asm!("csrr {}, mvendorid", out(reg) ret);
        },
        sbi_ext_base::GET_MARCHID => unsafe {
            asm!("csrr {}, marchid", out(reg) ret);
        },
        sbi_ext_base::GET_MIMPID => unsafe {
            asm!("csrr {}, mimpid", out(reg) ret);
        },
        _ => log::info!("Invalid get_m_x_id request!"),
    }
    //println!("Returning m_x_id {:x}",ret);
    return ret;
}

pub fn sbi_ext_srst_probe(_a0: usize) -> usize {
    //TODO For now this function pretends that srst extension probe works as expected.
    //If needed in the future, this must be implemented fully - refer to openSBI for this.
    return 1;
}

pub fn ecall_handler_failed() {
    //TODO: Print information about requested ecall.
    //log::info!("Cannot service SBI ecall - invalid ecall/Not supported by Tyche.");
}
