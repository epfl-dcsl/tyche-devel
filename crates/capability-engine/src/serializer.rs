//! Serializer
//!
//! This module expose an interface to serialize the internal capa-engine representation into a
//! inter-operable attestation format.

use crate::domain::DomainPool;
use crate::segment::{HandleIterator, RegionCapa, RegionPool};
use crate::{Capa, CapaError, Domain, Handle};

/// Serialization-Deserialization constants
#[rustfmt::skip]
pub mod serde {
    pub const MAGIC: [u8; 4] = *b"capa";
    pub const REGION_HEADER: u8 = 0b00000001;
    pub const DOMAIN_HEADER: u8 = 0b00000010;
    pub const END_MARKER:    u8 = 0b11111111;

    pub const REGION_ROOT:     u8 = 0b10000000;
    pub const REGION_ALIAS:    u8 = 0b10000001;
    pub const REGION_CARVE:    u8 = 0b10000010;
    pub const REGION_HAS_HASH: u8 = 0b10000101;
    pub const REGION_NO_HASH:  u8 = 0b10000100;

    pub const DOMAIN_CAPA_START: u8 = 0b01000000;
    pub const DOMAIN_CAPA_END:   u8 = 0b01000001;
    pub const CAPA_REGION:       u8 = 0b00100000;
    pub const CAPA_DOMAIN:       u8 = 0b00100001;
}

// ————————————————————————————————— Buffer ————————————————————————————————— //

struct Buffer<'a> {
    buff: &'a mut [u8],
    idx: usize,
}

impl<'a> Buffer<'a> {
    fn new(buff: &'a mut [u8]) -> Self {
        Self { buff, idx: 0 }
    }

    fn write_bytes<const N: usize>(&mut self, bytes: [u8; N]) -> Result<(), CapaError> {
        if self.idx + N > self.buff.len() {
            return Err(CapaError::OutOfMemory);
        }
        self.buff[self.idx..(self.idx + N)].copy_from_slice(&bytes);
        self.idx += N;
        Ok(())
    }

    fn u8(&mut self, val: u8) -> Result<(), CapaError> {
        self.write_bytes(val.to_le_bytes())
    }

    // fn u16(&mut self, val: u16) -> Result<(), CapaError> {
    //     self.write_bytes(val.to_le_bytes())
    // }

    fn u32(&mut self, val: u32) -> Result<(), CapaError> {
        self.write_bytes(val.to_le_bytes())
    }

    fn u64(&mut self, val: u64) -> Result<(), CapaError> {
        self.write_bytes(val.to_le_bytes())
    }
}

// ————————————————————————————— Serialization —————————————————————————————— //

pub(crate) fn serialize(
    buff: &mut [u8],
    domains: &DomainPool,
    regions: &RegionPool,
) -> Result<usize, CapaError> {
    let mut buff = Buffer::new(buff);
    buff.write_bytes(serde::MAGIC)?;
    serialize_regions(&mut buff, regions)?;
    serialize_domains(&mut buff, domains, regions)?;
    buff.u8(serde::END_MARKER)?;

    Ok(buff.idx + 1)
}

fn serialize_regions(buff: &mut Buffer, regions: &RegionPool) -> Result<(), CapaError> {
    buff.u8(serde::REGION_HEADER)?;
    let mut region_idx = 0;
    for h in regions {
        // Recursively serialize each tree, starting from the root
        if regions[h].is_root() {
            serialize_region(buff, h, &mut region_idx, u32::MAX, regions)?;
        }
    }
    buff.u8(serde::END_MARKER)?;

    Ok(())
}

/// Serialize a region and all its children.
fn serialize_region(
    buff: &mut Buffer,
    handle: Handle<RegionCapa>,
    idx: &mut u32,
    parent_idx: u32,
    regions: &RegionPool,
) -> Result<(), CapaError> {
    let region = &regions[handle];
    let region_idx = *idx;
    region.temporary_id.set(region_idx);
    *idx += 1;

    // Serialize region
    let kind = match region.kind {
        crate::segment::RegionKind::Root => serde::REGION_ROOT,
        crate::segment::RegionKind::Alias(_) => serde::REGION_ALIAS,
        crate::segment::RegionKind::Carve(_) => serde::REGION_CARVE,
    };
    buff.u8(kind)?;
    if !region.is_root() {
        buff.u32(parent_idx)?;
    }
    buff.u8(region.access.ops.bits())?;
    buff.u64(region.access.start as u64)?;
    buff.u64(region.access.end as u64)?;
    if let Some(hash) = &region.hash {
        buff.u8(serde::REGION_HAS_HASH)?;
        buff.u64(hash.len() as u64)?;
        for byte in hash {
            buff.u8(*byte)?;
        }
    } else {
        buff.u8(serde::REGION_NO_HASH)?;
    }

    // Serialize children
    for child in HandleIterator::child_list(handle, regions) {
        serialize_region(buff, child, idx, region_idx, regions)?;
    }

    Ok(())
}

fn serialize_domains(
    buff: &mut Buffer,
    domains: &DomainPool,
    regions: &RegionPool,
) -> Result<(), CapaError> {
    buff.u8(serde::DOMAIN_HEADER)?;

    // Set temporary IDs
    let mut idx = 0;
    for d in domains {
        domains[d].temporary_id.set(idx);
        idx += 1;
    }

    // Serialize domains
    for d in domains {
        let td = &domains[d];
        serialize_domain(buff, td, domains, regions)?;
    }

    buff.u8(serde::END_MARKER)?;
    Ok(())
}

fn serialize_domain(
    buff: &mut Buffer,
    td: &Domain,
    domains: &DomainPool,
    regions: &RegionPool,
) -> Result<(), CapaError> {
    buff.u64(td.temporary_id.get())?;
    buff.u64(td.monitor_interface())?;
    buff.u8(serde::DOMAIN_CAPA_START)?;
    for capa in td.iter_capa() {
        match capa {
            Capa::None | Capa::RegionRevoke(_) | Capa::Channel(_) | Capa::Switch { .. } => (),
            Capa::Region(h) => {
                buff.u8(serde::CAPA_REGION)?;
                buff.u64(regions[h].temporary_id.get() as u64)?;
            }
            Capa::Management(h) => {
                buff.u8(serde::CAPA_DOMAIN)?;
                buff.u64(domains[h].temporary_id.get())?;
            }
        }
    }
    buff.u8(serde::DOMAIN_CAPA_END)?;
    Ok(())
}
