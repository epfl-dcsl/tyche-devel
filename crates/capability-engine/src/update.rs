#![allow(dead_code)]

use core::{fmt, mem};

use crate::config::NB_UPDATES;
use crate::{Domain, Handle, LocalCapa};

pub type UpdateBuffer = Buffer<Update>;

#[derive(Debug, Clone, Copy)]
pub enum Update {
    PermissionUpdate {
        domain: Handle<Domain>,
    },
    TlbShootdown {
        core: usize,
    },
    RevokeDomain {
        domain: Handle<Domain>,
    },
    CreateDomain {
        domain: Handle<Domain>,
    },
    Switch {
        domain: Handle<Domain>,
        return_capa: LocalCapa,
        core: usize,
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
    UpdateTraps {
        trap: u64,
        core: usize,
    },
}

pub struct Buffer<U> {
    buff: [Option<U>; NB_UPDATES],
    head: usize,
}

impl<U> Buffer<U>
where
    U: Copy + fmt::Display,
{
    pub const fn new() -> Self {
        Buffer {
            buff: [None; NB_UPDATES],
            head: 0,
        }
    }

    pub fn push(&mut self, update: U) {
        log::trace!("Push {}", update);

        // Safety checks
        if self.head >= self.buff.len() {
            log::error!("Update buffer is full");
            panic!("Update buffer if full");
        }
        let None = self.buff[self.head] else {
            log::error!("Update buffer contains unapplied update");
            panic!("Update buffer contains unapplied update");
        };

        self.buff[self.head] = Some(update);
        self.head += 1;
    }

    pub fn pop(&mut self) -> Option<U> {
        if self.head == 0 {
            return None;
        }

        self.head -= 1;
        let update = mem::replace(&mut self.buff[self.head], None);

        match update {
            None => {
                // Safety checks, there should be no None on the buffer stack
                log::error!("Update buffer contains unapplied update");
                panic!("Update buffer contains unapplied update");
            }
            Some(update) => Some(update),
        }
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl fmt::Display for Update {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Update::PermissionUpdate { domain } => write!(f, "PermissionUpdate({})", domain),
            Update::RevokeDomain { domain } => write!(f, "RevokeDomain({})", domain),
            Update::CreateDomain { domain } => write!(f, "CreateDomain({})", domain),
            Update::TlbShootdown { core } => write!(f, "TlbShootdown({})", core),
            Update::Switch { domain, core, .. } => write!(f, "Switch({}, core {})", domain, core),
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
            Update::UpdateTraps { trap, core } => {
                write!(f, "UpdateTrap(bitmap {}, core {})", trap, core)
            }
        }
    }
}
