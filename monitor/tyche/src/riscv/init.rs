use core::arch::asm;
use core::sync::atomic::Ordering;

use capa_engine::{Domain, Handle};
use riscv_tyche::RVManifest;
use riscv_utils::{
    set_mip_ssip, AVAILABLE_HART_MASK, HART_START, HART_START_ADDR, HART_START_ARG1,
    NUM_HARTS_AVAILABLE,
};

use super::{arch, launch_guest};
use crate::debug::qemu;
use crate::riscv::cpuid;
use crate::riscv::platform::MonitorRiscv;

pub fn arch_entry_point(hartid: usize, manifest: RVManifest, log_level: log::LevelFilter) -> ! {
    if hartid == manifest.coldboot_hartid {
        logger::init(log_level);

        log::info!(
            "============= Hello from Second Stage on Hart ID: {} =============",
            hartid
        );
        log::info!(
            "Manifest Content: {:x} {:x} {:x} {:x} {:x}",
            manifest.coldboot_hartid,
            manifest.next_arg1,
            manifest.next_addr,
            manifest.next_mode,
            manifest.num_harts
        );
        let mhartid = cpuid();
        log::debug!("==========Coldboot MHARTID: {} ===========", mhartid);

        let mut t_num_harts = manifest.num_harts - 1;
        let mut available_harts_mask = 1;
        while t_num_harts > 0 {
            available_harts_mask = (available_harts_mask << 1) | 1;
            t_num_harts = t_num_harts - 1;
        }

        AVAILABLE_HART_MASK.store(available_harts_mask, Ordering::SeqCst);
        NUM_HARTS_AVAILABLE.store(manifest.num_harts, Ordering::SeqCst);

        MonitorRiscv::init();

        let mut domain = MonitorRiscv::start_initial_domain_on_cpu();

        log::info!("Initial domain is ready.");

        arch::init(hartid);

        //Set the active domain.
        MonitorRiscv::set_active_dom(hartid, domain);

        //monitor::do_debug();

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

        log::debug!(
            "MIP: {:x} MIE: {:x} MSTATUS: {:x} MEDELEG: {:x} MIDELEG: {:x}",
            mip,
            mie,
            mstatus,
            medeleg,
            mideleg
        );

        //TODO: Change function name to be arch independent. Not launching guest in RV.
        launch_guest(
            hartid,
            manifest.next_arg1,
            manifest.next_addr,
            manifest.next_mode,
        );
        qemu::exit(qemu::ExitCode::Success);
    } else {
        log::info!(
            "============= Hello again from Second Stage on Hart ID: {} =============",
            hartid
        );
        let mhartid = cpuid();
        log::debug!("========== Warmboot MHARTID: {} ===========", mhartid);

        //First set mtvec to Tyche's trap handler.
        arch::init(hartid);

        //spin loop until linux sends an ecall to start the hart.
        while !HART_START[hartid].load(Ordering::SeqCst) {
            //while true {
            core::hint::spin_loop();
        }

        log::info!("Done spinning for hart {}", hartid);

        let mut domain = MonitorRiscv::start_initial_domain_on_cpu();

        MonitorRiscv::set_active_dom(hartid, domain);

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

        log::debug!(
            "MIP: {:x} MIE: {:x} MSTATUS: {:x} MEDELEG: {:x} MIDELEG: {:x}",
            mip,
            mie,
            mstatus,
            medeleg,
            mideleg
        );

        launch_guest(hartid, jump_arg, jump_addr, manifest.next_mode);

        qemu::exit(qemu::ExitCode::Success);
    }
}
