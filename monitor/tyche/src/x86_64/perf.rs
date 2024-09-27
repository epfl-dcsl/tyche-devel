//! Performance measurement

use core::arch::x86_64;
use core::cmp;

use crate::arch::cpuid;

const PERF_ENABLED: bool = false;
const DISPLAY_DELAY: u64 = 50_000_000_000;

pub struct PerfContext {
    last_timestamp: u64,
    active: bool,
    last_display: u64,
    event: PerfEvent,
    stats: [PerfStats; NB_EVENTS],
}

pub struct PerfStats {
    count: u64,
    min: u64,
    max: u64,
    sum: u64,
    sum_square: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub enum PerfEvent {
    Other,
    Vmcall,
    VmcallSwitch,
    VmcallDuplicate,
    VmcallEnumerate,
    VmcallConfigure,
    VmcallConfigureCore,
    VmcallGetConfigCore,
    VmcallGetAllGp,
    VmcallWriteAllGp,
    VmcallWriteField,
    VmcallSelfConfigure,
    VmcallReturnToManager,
    VmcallGetHpa,
    IoInstr,
    Msr,
    VmxTimer,
    Cpuid,
    ControlRegisterAccess,
    EptViolation,
    ExternalInt,
    Exception,
    ApicAccess,
    VirtEoi,
    Xsetbv,
    Debug,
}

const NB_EVENTS: usize = 26;

static EVENTS: [PerfEvent; NB_EVENTS] = [
    PerfEvent::Other,
    PerfEvent::Vmcall,
    PerfEvent::VmcallSwitch,
    PerfEvent::VmcallDuplicate,
    PerfEvent::VmcallEnumerate,
    PerfEvent::VmcallConfigure,
    PerfEvent::VmcallConfigureCore,
    PerfEvent::VmcallGetConfigCore,
    PerfEvent::VmcallGetAllGp,
    PerfEvent::VmcallWriteAllGp,
    PerfEvent::VmcallWriteField,
    PerfEvent::VmcallSelfConfigure,
    PerfEvent::VmcallGetHpa,
    PerfEvent::VmcallReturnToManager,
    PerfEvent::Cpuid,
    PerfEvent::IoInstr,
    PerfEvent::Msr,
    PerfEvent::VmxTimer,
    PerfEvent::ControlRegisterAccess,
    PerfEvent::EptViolation,
    PerfEvent::ExternalInt,
    PerfEvent::Exception,
    PerfEvent::ApicAccess,
    PerfEvent::VirtEoi,
    PerfEvent::Xsetbv,
    PerfEvent::Debug,
];

fn rdtsc() -> u64 {
    unsafe { x86_64::_rdtsc() }
}

impl PerfContext {
    pub const fn new() -> Self {
        const PERF_STATS: PerfStats = PerfStats::new();

        Self {
            last_timestamp: 0,
            active: false,
            last_display: 0,
            event: PerfEvent::Other,
            stats: [PERF_STATS; NB_EVENTS],
        }
    }

    /// Starts the counter
    pub fn start(&mut self) {
        if !PERF_ENABLED {
            return;
        }

        assert!(!self.active);
        self.active = true;
        self.event = PerfEvent::Other;
        self.last_timestamp = rdtsc();
    }

    /// Commit the counter and update statistics
    pub fn commit(&mut self) {
        if !PERF_ENABLED {
            return;
        }

        assert!(self.active);
        let timestamp = rdtsc();
        let ts = timestamp - self.last_timestamp;
        self.stats[self.event as usize].commit(ts);
        self.active = false;
    }

    /// Record the type of event for which stats are currently displayed
    pub fn event(&mut self, event: PerfEvent) {
        if !PERF_ENABLED {
            return;
        }

        self.event = event;
    }

    /// Displays the stats, only if enough time elasped
    pub fn display_stats(&mut self) {
        if !PERF_ENABLED {
            return;
        }

        // We only print stats for CPU 0 for now
        if cpuid() != 0 {
            return;
        }

        // Check if enough time has elapsed
        let ts = rdtsc();
        if ts < self.last_display + DISPLAY_DELAY {
            return;
        }

        log::info!("----- Perf Events ------");
        log::info!("ts:    {}", ts - self.last_display);

        let mut sum = 0;
        let mut sum_square = 0;
        let mut min = u64::MAX;
        let mut max = 0;
        let mut count = 0;

        // Compute global statistics
        for event in &EVENTS {
            let stats = &self.stats[*event as usize];
            sum += stats.sum;
            sum_square += stats.sum_square;
            min = cmp::min(stats.min, min);
            max = cmp::max(stats.max, max);
            count += stats.count;
        }

        // Display per event statistics
        for event in &EVENTS {
            let stats = &self.stats[*event as usize];
            if stats.count != 0 {
                // Compute percentage
                // Source: https://stackoverflow.com/a/20790402
                let a = stats.count;
                let b = count;
                let res = (10000 * a + b / 2) / b;
                let percent_int = res / 100;
                let percent_frac = res % 100;

                // Compute other metrics
                let mean = stats.sum / stats.count;
                let square_mean = mean * mean;
                let std = u64::isqrt(stats.sum_square / stats.count - square_mean);
                log::info!(
                    "{:<20?} {:>7}     ({}.{:02}%)",
                    event,
                    stats.count,
                    percent_int,
                    percent_frac
                );
                log::info!(
                    "  Cycles: {:>7} +/- {:>7}   range [{:>7}, {:>7}]",
                    mean,
                    std,
                    stats.min,
                    stats.max
                );
            }
        }

        if count != 0 {
            let mean = sum / count;
            let square_mean = mean * mean;
            let std = u64::isqrt(sum_square / count - square_mean);
            log::info!("Total: {}", count);
            log::info!(
                "  Cycles: {:>7} +/- {:>7}   range [{:>7}, {:>7}]",
                mean,
                std,
                min,
                max
            );
        }

        log::info!("------------------------");

        for event in &EVENTS {
            let stats = &mut self.stats[*event as usize];
            stats.count = 0;
            stats.min = u64::MAX;
            stats.max = 0;
            stats.sum = 0;
            stats.sum_square = 0;
        }
        self.last_display = ts;
    }
}

impl PerfStats {
    pub const fn new() -> Self {
        Self {
            count: 0,
            min: u64::MAX,
            max: 0,
            sum: 0,
            sum_square: 0,
        }
    }

    fn commit(&mut self, ts: u64) {
        self.count += 1;
        self.min = cmp::min(self.min, ts);
        self.max = cmp::max(self.max, ts);
        self.sum += ts;
        self.sum_square += ts * ts;
    }
}
