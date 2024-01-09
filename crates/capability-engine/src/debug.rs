//! Debug utilities

/// Run a check when enabled at compile time.
macro_rules! debug_check {
    // For now we always run the checks, but in the future we will enable them with a feature
    ($check:expr) => {
        $check
    };
}

pub(crate) use debug_check;
