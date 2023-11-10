#![no_std]

use core::sync::atomic::{AtomicBool, Ordering};

use log::{LevelFilter, Metadata, Record};
use qemu::_print;
use spin::Mutex;

static LOGGER: LockedLogger = LockedLogger(Mutex::new(Logger {}));
static IS_INITIALIZED: AtomicBool = AtomicBool::new(false);

struct LockedLogger(Mutex<Logger>);

struct Logger {}

impl log::Log for LockedLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.0.lock().enabled(metadata)
    }

    fn log(&self, record: &Record) {
        self.0.lock().log(record)
    }

    fn flush(&self) {}
}

impl Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            _print(core::format_args!(
                "[{} | {}] {}\r\n",
                record.level(),
                record.target(),
                record.args()
            ))
        }
    }
}

pub fn init(level: LevelFilter) {
    match IS_INITIALIZED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => {
            log::set_logger(&LOGGER).unwrap();
            log::set_max_level(level);
        }
        Err(_) => {
            log::warn!("Logger is already initialized, skipping init");
        }
    };
}
