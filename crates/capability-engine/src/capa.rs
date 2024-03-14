//! Capabilities

use core::fmt;

use crate::domain::{Domain, DomainPool};
use crate::gen_arena::Handle;
use crate::segment::{RegionCapa, RegionPool};
use crate::{CapaError, MemOps};

#[derive(Clone, Copy, Debug)]
pub enum Capa {
    None,
    Region(Handle<RegionCapa>),
    RegionRevoke(Handle<RegionCapa>),
    Management(Handle<Domain>),
    #[allow(dead_code)] // TODO: remove once channels are implemented
    Channel(Handle<Domain>),
    Switch {
        to: Handle<Domain>,
        core: usize,
    },
}

#[derive(Clone, Debug)]
pub enum CapaInfo {
    Region {
        start: usize,
        end: usize,
        unique: bool,
        children: bool,
        ops: MemOps,
    },
    RegionRevoke {
        start: usize,
        end: usize,
        confidential: bool,
        ops: MemOps,
    },
    Management {
        domain_id: usize,
        sealed: bool,
    },
    Channel {
        domain_id: usize,
    },
    Switch {
        domain_id: usize,
    },
}

impl CapaInfo {
    pub fn serialize(&self) -> (usize, usize, u16) {
        let v1;
        let mut v2 = 0;
        let capa_type: u8;
        let mut flags: u8 = 0;

        match self {
            CapaInfo::Region {
                start,
                end,
                unique,
                children: _,
                ops,
            } => {
                v1 = *start;
                v2 = *end;
                // New regions are always active
                flags |= 1;
                if *unique {
                    flags |= 1 << 1;
                }
                flags |= ops.bits() << 2;
                capa_type = capa_type::NEW_REGION;
            }
            CapaInfo::RegionRevoke {
                start,
                end,
                confidential,
                ops,
            } => {
                v1 = *start;
                v2 = *end;
                if *confidential {
                    flags |= 1 << 1;
                }
                flags |= ops.bits() << 2;
                capa_type = capa_type::REGION_REVOKE;
            }
            CapaInfo::Management { domain_id, sealed } => {
                v1 = *domain_id;
                if *sealed {
                    v2 = 1 << 1;
                } else {
                    v2 = 1 << 0;
                }
                capa_type = capa_type::MANAGEMENT;
            }
            CapaInfo::Channel { domain_id } => {
                v1 = *domain_id;
                capa_type = capa_type::CHANNEL;
            }
            CapaInfo::Switch { domain_id } => {
                v1 = *domain_id;
                capa_type = capa_type::SWITCH;
            }
        }

        let v3 = capa_type as u16 + ((flags as u16) << 8);
        (v1, v2, v3)
    }

    // TODO: write some tests
    pub fn deserialize(v1: usize, v2: usize, v3: u16) -> Result<Self, CapaError> {
        let capa_type = (v3 & 0xFF) as u8;
        let flags = v3 >> 8;
        let capa_info = match capa_type {
            capa_type::MANAGEMENT => Self::Management {
                domain_id: v1,
                sealed: v2 == 2,
            },
            capa_type::CHANNEL => Self::Channel { domain_id: v1 },
            capa_type::SWITCH => Self::Switch { domain_id: v1 },
            capa_type::NEW_REGION => {
                let unique = (flags & 0b10) != 0;
                let ops = MemOps::from_bits(flags as u8 >> 2).unwrap_or(MemOps::NONE);
                Self::Region {
                    start: v1,
                    end: v2,
                    unique: unique,
                    children: false, //TODO fix
                    ops: ops,
                }
            }
            _ => {
                return Err(CapaError::CouldNotDeserializeInfo);
            }
        };
        Ok(capa_info)
    }
}

#[rustfmt::skip]
pub mod capa_type {
    pub const MANAGEMENT:    u8 = 1;
    pub const CHANNEL:       u8 = 2;
    pub const SWITCH:        u8 = 3;
    pub const NEW_REGION:    u8 = 4;
    pub const REGION_REVOKE: u8 = 5;
}

impl Capa {
    pub(crate) fn management(managee: Handle<Domain>) -> Self {
        Capa::Management(managee)
    }

    pub fn as_region(self) -> Result<Handle<RegionCapa>, CapaError> {
        match self {
            Capa::Region(region) => Ok(region),
            _ => Err(CapaError::WrongCapabilityType),
        }
    }

    pub fn as_management(self) -> Result<Handle<Domain>, CapaError> {
        match self {
            Capa::Management(domain) => Ok(domain),
            _ => Err(CapaError::WrongCapabilityType),
        }
    }

    pub fn as_channel(self) -> Result<Handle<Domain>, CapaError> {
        match self {
            Capa::Management(domain) => Ok(domain),
            Capa::Channel(domain) => Ok(domain),
            _ => Err(CapaError::WrongCapabilityType),
        }
    }

    pub fn as_domain(self) -> Result<Handle<Domain>, CapaError> {
        match self {
            Capa::Management(domain) => Ok(domain),
            Capa::Channel(domain) => Ok(domain),
            _ => Err(CapaError::WrongCapabilityType),
        }
    }

    pub fn as_switch(self) -> Result<(Handle<Domain>, usize), CapaError> {
        match self {
            Capa::Switch { to, core } => Ok((to, core)),
            _ => Err(CapaError::WrongCapabilityType),
        }
    }

    pub(crate) fn info(self, regions: &RegionPool, domains: &DomainPool) -> Option<CapaInfo> {
        match self {
            Capa::None => None,
            Capa::Region(h) => {
                let region = &regions[h];
                Some(CapaInfo::Region {
                    start: region.access.start,
                    end: region.access.end,
                    unique: region.is_confidential,
                    children: region.child_list_head.is_some(),
                    ops: region.access.ops,
                })
            }
            Capa::RegionRevoke(h) => {
                let region = &regions[h];
                Some(CapaInfo::RegionRevoke {
                    start: region.access.start,
                    end: region.access.end,
                    confidential: region.is_confidential,
                    ops: region.access.ops,
                })
            }
            Capa::Management(h) => {
                let domain = &domains[h];
                Some(CapaInfo::Management {
                    domain_id: domain.id(),
                    sealed: domain.is_sealed(),
                })
            }
            Capa::Channel(h) => {
                let domain = &domains[h];
                Some(CapaInfo::Channel {
                    domain_id: domain.id(),
                })
            }
            Capa::Switch { to, .. } => {
                let domain = &domains[to];
                Some(CapaInfo::Switch {
                    domain_id: domain.id(),
                })
            }
        }
    }
}

pub trait IntoCapa {
    fn into_capa(self) -> Capa;
}

impl IntoCapa for Handle<RegionCapa> {
    fn into_capa(self) -> Capa {
        Capa::Region(self)
    }
}

impl IntoCapa for Capa {
    #[inline]
    fn into_capa(self) -> Capa {
        self
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //

impl fmt::Display for CapaInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapaInfo::Region {
                start,
                end,
                unique,
                children,
                ops,
            } => {
                let c = if *unique { 'U' } else { '_' };
                let p = if *children { 'P' } else { '_' };
                write!(
                    f,
                    "Region([0x{:x}, 0x{:x} | {}{}{}])",
                    start, end, p, c, ops
                )
            }
            CapaInfo::RegionRevoke {
                start,
                end,
                confidential,
                ops,
            } => {
                let c = if *confidential { 'C' } else { '_' };
                write!(
                    f,
                    "RegionRevoke([0x{:x}, 0x{:x} | {}{}])",
                    start, end, c, ops
                )
            }
            CapaInfo::Management { domain_id, sealed } => {
                let s = if *sealed { 'S' } else { '_' };
                write!(f, "Management({} | {})", domain_id, s)
            }
            CapaInfo::Channel { domain_id } => {
                write!(f, "Channel({})", domain_id)
            }
            CapaInfo::Switch { domain_id } => {
                write!(f, "Switch({})", domain_id)
            }
        }
    }
}
