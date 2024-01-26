use core::sync::atomic::Ordering;

use core::arch::asm;

use capa_engine::{Domain, Handle};
use riscv_utils::{HART_START, HART_START_ARG1, HART_START_ADDR, set_mip_ssip};

use super::{arch, guest, launch_guest, monitor};
use crate::debug::qemu;
use crate::riscv::cpuid;

pub fn arch_entry_point(
    hartid: usize,
    arg1: usize,
    next_addr: usize,
    next_mode: usize,
    coldboot: bool,
    log_level: log::LevelFilter,
) -> ! {
    if coldboot {
        logger::init(log_level);

        log::info!("============= Hello from Second Stage on Hart ID: {} =============", hartid);
        let mhartid = cpuid();
        log::debug!("==========Coldboot MHARTID: {} ===========", mhartid); 

        monitor::init();

        let mut domain = monitor::start_initial_domain_on_cpu();

        log::info!("Initial domain is ready.");

        arch::init(hartid);

        unsafe {
            //Set the active domain.
            guest::set_active_dom(domain);
        }

        monitor::do_debug();

        let mip: usize;
        let mie: usize;
        let mstatus: usize;
        let medeleg: usize;
        let mideleg: usize; 

        unsafe {
            asm!("csrr {}, mip", out(reg) mip);
            asm!("csrr {}, mie", out(reg) mie);
            asm!("csrr {}, mstatus", out(reg) mstatus);
            asm!("csrr {}, medeleg", out(reg) medeleg);
            asm!("csrr {}, mideleg", out(reg) mideleg);
        }

        log::info!("MIP: {:x} MIE: {:x} MSTATUS: {:x} MEDELEG: {:x} MIDELEG: {:x}", mip, mie, mstatus, medeleg, mideleg);

        //TODO: Change function name to be arch independent. Not launching guest in RV.
        launch_guest(hartid, arg1, next_addr, next_mode);
        qemu::exit(qemu::ExitCode::Success);

    } else {
        log::info!("============= Hello again from Second Stage on Hart ID: {} =============", hartid);
        let mhartid = cpuid();
        log::debug!("========== Warmboot MHARTID: {} ===========", mhartid);

        //First set mtvec to Tyche's trap handler. 
        arch::init(hartid);

        //spin loop until linux sends an ecall to start the hart. 
        while !HART_START[hartid].load(Ordering::SeqCst) {
        //while true {
            core::hint::spin_loop();
        }

        log::info!("Done spinning for hart {}",hartid);

        //let mut domain = monitor::start_initial_domain_on_cpu(); 

        //unsafe {
        //    trap::set_active_dom(hartid, domain);
        //}

        let jump_addr = HART_START_ADDR[hartid].load(Ordering::SeqCst);
        let jump_arg = HART_START_ARG1[hartid].load(Ordering::SeqCst);

        log::info!("Next_addr: {:x} Next_arg1: {:x}", jump_addr, jump_arg);

        //set_mip_ssip();
        let mip: usize;
        let mie: usize;
        let mstatus: usize;
        let medeleg: usize;
        let mideleg: usize; 

        unsafe {
            asm!("csrr {}, mip", out(reg) mip);
            asm!("csrr {}, mie", out(reg) mie);
            asm!("csrr {}, mstatus", out(reg) mstatus);
            asm!("csrr {}, medeleg", out(reg) medeleg);
            asm!("csrr {}, mideleg", out(reg) mideleg);
            //asm!("csrsi mip, 2");
        }

        log::info!("MIP: {:x} MIE: {:x} MSTATUS: {:x} MEDELEG: {:x} MIDELEG: {:x}", mip, mie, mstatus, medeleg, mideleg);

        launch_guest(hartid, jump_arg, jump_addr, next_mode);

        qemu::exit(qemu::ExitCode::Success);
    }
}
