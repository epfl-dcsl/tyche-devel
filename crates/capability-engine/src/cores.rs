//§ Cores

use crate::config::NB_CORES;
use crate::domain::DomainHandle;
use crate::gen_arena::Handle;
use crate::CapaError;

pub(crate) type CoreList = [Core; NB_CORES];

pub struct Core {
    /// The domain currently running on the core.
    domain: DomainHandle,
    /// To ensure cores are not initialized twice by mistake.
    is_initialized: bool,
}

impl Core {
    /// Creates a fresh core running an invalid domain.
    pub const fn new() -> Self {
        Self {
            domain: Handle::new_invalid(),
            is_initialized: false,
        }
    }

    pub fn initialize(&mut self, domain: DomainHandle) -> Result<(), CapaError> {
        if self.is_initialized {
            log::warn!("Tried to initialize already initialized domain");
            return Err(CapaError::InvalidCore);
        }

        self.domain = domain;
        self.is_initialized = true;
        Ok(())
    }
}
