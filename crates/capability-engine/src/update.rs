#![allow(dead_code)]

use core::fmt;

use crate::config::NB_UPDATES;
use crate::{CapaError, Domain, Handle, LocalCapa};

pub type UpdateBuffer = Buffer<Update>;

#[derive(Debug, Clone, Copy)]
pub enum Update {
    PermissionUpdate {
        domain: Handle<Domain>,
        core_map: u64,
    },
    RevokeDomain {
        manager: Handle<Domain>,
        mgmt_capa: LocalCapa,
        domain: Handle<Domain>,
    },
    CreateDomain {
        domain: Handle<Domain>,
    },
    Switch {
        domain: Handle<Domain>,
        return_capa: LocalCapa,
        core: usize,
        delta: usize,
    },
    Trap {
        /// The manager responsible for handling the trap
        manager: Handle<Domain>,
        /// The trap to handle
        trap: u64,
        /// Trap information
        info: u64,
        /// Core on which the trap happenend
        core: usize,
    },
    Cleanup {
        start: usize,
        end: usize,
    },
}

pub struct Buffer<U> {
    buff: [Option<U>; NB_UPDATES + 1],
    read: usize,
    write: usize,
}

impl<U> Buffer<U>
where
    U: Copy + fmt::Display,
{
    pub const fn new() -> Self {
        Buffer {
            buff: [None; NB_UPDATES + 1],
            read: 0,
            write: 0,
        }
    }

    pub fn push(&mut self, update: U) -> Result<(), CapaError> {
        log::trace!("Push {}", update);

        let next_write = (self.write + 1) % self.buff.len();
        if next_write == self.read {
            log::error!("Update buffer is full");
            return Err(CapaError::OutOfMemory);
        }
        self.buff[self.write] = Some(update);
        self.write = next_write;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<U> {
        if self.read == self.write {
            None // Buffer is empty
        } else {
            let item = self.buff[self.read].take(); // Take the item out of the buffer
            self.read = (self.read + 1) % self.buff.len();
            item
        }
    }

    pub fn contains<F>(&self, filter: F) -> bool
    where
        F: Fn(U) -> bool,
    {
        let mut index = self.read;
        while index != self.write {
            if filter(self.buff[index].unwrap()) {
                return true;
            }
            index = (index + 1) % self.buff.len();
        }
        return false;
    }

    pub fn capacity(&self) -> usize {
        let available = if self.write >= self.read {
            // Write pointer is ahead of or equal to read pointer
            self.buff.len() - (self.write - self.read)
        } else {
            // Read pointer has looped around and is ahead of write pointer
            self.read - self.write
        };

        // We keep one empty space
        available - 1
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl fmt::Display for Update {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Update::PermissionUpdate { domain, .. } => {
                write!(f, "PermissionUpdate({})", domain)
            }
            Update::RevokeDomain {
                manager,
                mgmt_capa,
                domain,
            } => {
                write!(f, "RevokeDomain({}, {:?}, {})", manager, mgmt_capa, domain)
            }
            Update::CreateDomain { domain } => write!(f, "CreateDomain({})", domain),
            Update::Switch { domain, core, .. } => write!(f, "Switch({}, core {})", domain, core),
            Update::Cleanup { start, end } => write!(f, "Cleanup([0x{:x}, 0x{:x}])", start, end),
            Update::Trap {
                manager,
                trap,
                info: _,
                core,
            } => write!(
                f,
                "Trap(manager: {}, trap: {}, core: {})",
                manager, trap, core
            ),
        }
    }
}
