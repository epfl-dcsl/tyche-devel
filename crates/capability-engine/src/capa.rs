//! Capabilities

use core::fmt;

use crate::context::Context;
use crate::domain::{Domain, DomainPool};
use crate::gen_arena::Handle;
use crate::region_capa::{RegionCapa, RegionPool};
use crate::CapaError;

#[derive(Clone, Copy, Debug)]
pub enum Capa {
    None,
    Region(Handle<RegionCapa>),
    Management(Handle<Domain>),
    #[allow(dead_code)] // TODO: remove once channels are implemented
    Channel(Handle<Domain>),
    Switch {
        to: Handle<Domain>,
        ctx: Handle<Context>,
    },
}

#[derive(Clone, Debug)]
pub enum CapaInfo {
    Region {
        start: usize,
        end: usize,
        active: bool,
        confidential: bool,
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
                active,
                confidential,
            } => {
                v1 = *start;
                v2 = *end;
                if *active {
                    flags |= 1 << 0;
                }
                if *confidential {
                    flags |= 1 << 1;
                }
                capa_type = capa_type::REGION;
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
            capa_type::REGION => {
                let active = (flags & 0b01) != 0;
                let confidential = (flags & 0b10) != 0;
                Self::Region {
                    start: v1,
                    end: v2,
                    active,
                    confidential,
                }
            }
            capa_type::MANAGEMENT => Self::Management {
                domain_id: v1,
                sealed: v2 == 2,
            },
            capa_type::CHANNEL => Self::Channel { domain_id: v1 },
            capa_type::SWITCH => Self::Switch { domain_id: v1 },
            _ => {
                return Err(CapaError::CouldNotDeserializeInfo);
            }
        };
        Ok(capa_info)
    }
}

#[rustfmt::skip]
pub mod capa_type {
    pub const REGION:     u8 = 0;
    pub const MANAGEMENT: u8 = 1;
    pub const CHANNEL:    u8 = 2;
    pub const SWITCH:     u8 = 3; 
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

    pub fn as_switch(self) -> Result<(Handle<Domain>, Handle<Context>), CapaError> {
        match self {
            Capa::Switch { to, ctx } => Ok((to, ctx)),
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
                    active: region.is_active,
                    confidential: region.is_confidential,
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
                active,
                confidential,
            } => {
                let a = if *active { 'A' } else { '_' };
                let c = if *confidential { 'C' } else { '_' };
                write!(f, "Region([0x{:x}, 0x{:x} | {}{}])", start, end, a, c)
            }
            CapaInfo::Management { domain_id, sealed } => {
                let s = if *sealed { 'S' } else { '_' };
                write!(f, "Management({}| {})", domain_id, s)
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
