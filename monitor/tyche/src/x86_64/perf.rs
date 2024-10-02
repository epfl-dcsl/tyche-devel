//! Performance measurement

use core::arch::x86_64;
use core::cmp;

use capa_engine::config::NB_CORES;

use crate::arch::cpuid;

const PERF_ENABLED: bool = false;
const DISPLAY_CORE: usize = 4;
const DISPLAY_DELAY: u64 = 50_000_000_000;
const MAX_STEPS: usize = 5;

const DEFAULT_PERF_CONTEXT: PerfContext = PerfContext::new();
static mut PERF_CONTEXTS: [PerfContext; NB_CORES] = [DEFAULT_PERF_CONTEXT; NB_CORES];

struct PerfContext {
    last_timestamp: u64,
    active: bool,
    last_display: u64,
    event: PerfEvent,
    stats: [PerfStats; NB_EVENTS],
    steps: [(u64, PerfStats); MAX_STEPS],
}

struct PerfStats {
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

pub fn start() {
    if !PERF_ENABLED {
        return;
    }

    unsafe { get_perf_ctx().start() }
}

pub fn commit() {
    if !PERF_ENABLED {
        return;
    };

    unsafe { get_perf_ctx().commit() }
}

#[allow(unused)]
pub fn start_step(step: usize) {
    if !PERF_ENABLED {
        return;
    }

    unsafe { get_perf_ctx().start_step(step) }
}

#[allow(unused)]
pub fn commit_step(step: usize) {
    if !PERF_ENABLED {
        return;
    };

    unsafe { get_perf_ctx().commit_step(step) }
}

pub fn event(event: PerfEvent) {
    if !PERF_ENABLED {
        return;
    }

    unsafe { get_perf_ctx().event(event) }
}

pub fn display_stats() {
    if !PERF_ENABLED {
        return;
    }

    unsafe { get_perf_ctx().display_stats() }
}

/// SAFETY: we have a single thread of control per core and interrupts disabled.
/// To be safe this function must never be called if another reference is still alive on that
/// core.
unsafe fn get_perf_ctx() -> &'static mut PerfContext {
    &mut PERF_CONTEXTS[cpuid()]
}

impl PerfContext {
    pub const fn new() -> Self {
        const PERF_STATS: PerfStats = PerfStats::new();
        const PERF_TS: (u64, PerfStats) = (0, PERF_STATS);

        Self {
            last_timestamp: 0,
            active: false,
            last_display: 0,
            event: PerfEvent::Other,
            stats: [PERF_STATS; NB_EVENTS],
            steps: [PERF_TS; MAX_STEPS],
        }
    }

    /// Starts the counter
    fn start(&mut self) {
        if !PERF_ENABLED {
            return;
        }

        assert!(!self.active);
        self.active = true;
        self.event = PerfEvent::Other;
        self.last_timestamp = rdtsc();
    }

    /// Commit the counter and update statistics
    fn commit(&mut self) {
        if !PERF_ENABLED {
            return;
        }

        assert!(self.active);
        let timestamp = rdtsc();
        let ts = timestamp - self.last_timestamp;
        self.stats[self.event as usize].commit(ts);
        self.active = false;
    }

    /// Starts the custom counter
    fn start_step(&mut self, step: usize) {
        if !PERF_ENABLED {
            return;
        }

        self.steps[step].0 = rdtsc();
    }

    /// Commit the counter and update statistics
    fn commit_step(&mut self, step: usize) {
        if !PERF_ENABLED {
            return;
        }

        let timestamp = rdtsc();
        let ts = timestamp - self.steps[step].0;
        self.steps[step].1.commit(ts);
    }

    /// Record the type of event for which stats are currently displayed
    fn event(&mut self, event: PerfEvent) {
        if !PERF_ENABLED {
            return;
        }

        self.event = event;
    }

    /// Displays the stats, only if enough time elasped
    fn display_stats(&mut self) {
        if !PERF_ENABLED {
            return;
        }

        // We only print stats for one CPU for now
        if cpuid() != DISPLAY_CORE {
            return;
        }

        // Check if enough time has elapsed
        let ts = rdtsc();
        if ts < self.last_display + DISPLAY_DELAY {
            return;
        }

        log::info!("----- Perf Events ------");
        log::info!("ts:    {} -- core {}", ts - self.last_display, cpuid());

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

        for (step_id, (_, step)) in self.steps.iter().enumerate() {
            if step.count != 0 {
                let step = step;
                // Compute other metrics
                let mean = step.sum / step.count;
                let square_mean = mean * mean;
                let std = u64::isqrt(step.sum_square / step.count - square_mean);
                log::info!("Step {}: {:>7}", step_id, step.count);
                log::info!(
                    "  Cycles: {:>7} +/- {:>7}   range [{:>7}, {:>7}]",
                    mean,
                    std,
                    step.min,
                    step.max
                );
            }
        }

        log::info!("------------------------");

        for event in &EVENTS {
            self.stats[*event as usize].reset();
        }
        for (_, step) in &mut self.steps {
            step.reset();
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

    fn reset(&mut self) {
        self.count = 0;
        self.min = u64::MAX;
        self.max = 0;
        self.sum = 0;
        self.sum_square = 0;
    }
}
