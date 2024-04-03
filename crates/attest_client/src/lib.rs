mod deserializer;

use core::fmt;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Index, IndexMut};

pub use capa_engine::{permission, MemOps};
pub use deserializer::deserialize;

#[derive(Clone, Copy)]
pub enum RegionKind {
    Root,
    Alias(Handle<Region>),
    Carve(Handle<Region>),
}

pub struct Region {
    start: u64,
    end: u64,
    ops: MemOps,
    kind: RegionKind,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capa {
    Region(Handle<Region>),
    Management(Handle<Domain>),
}

pub trait IntoCapa {
    fn into_capa(self) -> Capa;
}

impl IntoCapa for Handle<Region> {
    fn into_capa(self) -> Capa {
        Capa::Region(self)
    }
}

impl IntoCapa for Handle<Domain> {
    fn into_capa(self) -> Capa {
        Capa::Management(self)
    }
}

pub struct Domain {
    id: u64,
    capa: Vec<Capa>,
    permissions: u64,
}

impl Domain {
    pub fn new(id: u64, permissions: u64) -> Self {
        Domain {
            id,
            permissions,
            capa: Vec::new(),
        }
    }

    pub fn add(&mut self, capa: impl IntoCapa) -> &mut Self {
        self.capa.push(capa.into_capa());
        self
    }
}

pub struct Context {
    regions: Arena<Region>,
    domains: Arena<Domain>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            regions: Arena::new(),
            domains: Arena::new(),
        }
    }

    pub fn root(&mut self, start: u64, end: u64, ops: MemOps) -> Handle<Region> {
        // TODO: check validity
        let region = Region {
            start,
            end,
            ops,
            kind: RegionKind::Root,
        };
        self.regions.push(region)
    }

    pub fn alias(
        &mut self,
        parent: Handle<Region>,
        start: u64,
        end: u64,
        ops: MemOps,
    ) -> Handle<Region> {
        // TODO: check validity
        let region = Region {
            start,
            end,
            ops,
            kind: RegionKind::Alias(parent),
        };
        self.regions.push(region)
    }

    pub fn carve(
        &mut self,
        parent: Handle<Region>,
        start: u64,
        end: u64,
        ops: MemOps,
    ) -> Handle<Region> {
        // TODO: check validity
        let region = Region {
            start,
            end,
            ops,
            kind: RegionKind::Carve(parent),
        };
        self.regions.push(region)
    }

    pub fn add_domain(&mut self, id: u64, permissions: u64) -> Handle<Domain> {
        self.domains.push(Domain {
            id,
            permissions,
            capa: Vec::new(),
        })
    }
}

impl Index<Handle<Domain>> for Context {
    type Output = Domain;

    fn index(&self, handle: Handle<Domain>) -> &Self::Output {
        &self.domains[handle]
    }
}

impl IndexMut<Handle<Domain>> for Context {
    fn index_mut(&mut self, handle: Handle<Domain>) -> &mut Self::Output {
        &mut self.domains[handle]
    }
}

// ————————————————————————————————— Error —————————————————————————————————— //

pub enum AttestError {}

// ————————————————————————————————— Arena —————————————————————————————————— //

pub struct Arena<T> {
    store: Vec<T>,
}

pub struct Handle<T> {
    idx: usize,
    _t: PhantomData<T>,
}

impl<T> Clone for Handle<T> {
    fn clone(&self) -> Self {
        Self {
            idx: self.idx,
            _t: PhantomData,
        }
    }
}

impl<T> Copy for Handle<T> {}

impl<T> Eq for Handle<T> {}

impl<T> PartialEq for Handle<T> {
    fn eq(&self, other: &Self) -> bool {
        self.idx == other.idx
    }
}

impl<T> Hash for Handle<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.idx.hash(state);
    }
}

impl<T> Arena<T> {
    pub fn new() -> Self {
        Self { store: Vec::new() }
    }

    pub fn push(&mut self, item: T) -> Handle<T> {
        let idx = self.store.len();
        self.store.push(item);
        Handle {
            idx,
            _t: PhantomData,
        }
    }

    pub fn as_handle(&self, idx: usize) -> Option<Handle<T>> {
        if self.store.get(idx).is_some() {
            Some(Handle {
                idx,
                _t: PhantomData,
            })
        } else {
            None
        }
    }

    pub fn as_unknown_handle(&self, idx: usize) -> Handle<T> {
        Handle {
            idx,
            _t: PhantomData,
        }
    }
}

impl<T> Index<Handle<T>> for Arena<T> {
    type Output = T;

    fn index(&self, handle: Handle<T>) -> &Self::Output {
        &self.store[handle.idx]
    }
}

impl<T> IndexMut<Handle<T>> for Arena<T> {
    fn index_mut(&mut self, handle: Handle<T>) -> &mut Self::Output {
        &mut self.store[handle.idx]
    }
}

// ———————————————————————————————— Display ————————————————————————————————— //

fn separator(f: &mut fmt::Formatter<'_>, first: &mut bool) -> fmt::Result {
    if *first {
        *first = false;
    } else {
        write!(f, " | ")?;
    }

    Ok(())
}

fn display_permissions(f: &mut fmt::Formatter<'_>, permissions: u64) -> fmt::Result {
    let mut first = true;
    if permissions & permission::SPAWN != 0 {
        separator(f, &mut first)?;
        write!(f, "SPAWN")?;
    }
    if permissions & permission::SEND != 0 {
        separator(f, &mut first)?;
        write!(f, "SEND")?;
    }
    if permissions & permission::ALIAS != 0 {
        separator(f, &mut first)?;
        write!(f, "ALIAS")?;
    }
    if permissions & permission::CARVE != 0 {
        separator(f, &mut first)?;
        write!(f, "CARVE")?;
    }
    if permissions == permission::NONE {
        write!(f, "NONE")?;
    }

    Ok(())
}

fn display_capas(f: &mut fmt::Formatter<'_>, capas: &Vec<Capa>) -> fmt::Result {
    let mut first = true;
    for capa in capas.iter() {
        if first {
            first = false;
        } else {
            write!(f, ", ")?;
        }
        match capa {
            Capa::Region(h) => write!(f, "r{}", h.idx)?,
            Capa::Management(h) => write!(f, "d{}", h.idx)?,
        }
    }

    if !first {
        write!(f, " ")?;
    }

    Ok(())
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Attestation {{")?;
        let mut idx = 0;
        for region in &self.regions.store {
            match region.kind {
                RegionKind::Root => {
                    let cleanup = if region.ops.contains(MemOps::CLEANUP) {
                        " | CLEANUP"
                    } else {
                        ""
                    };
                    let vital = if region.ops.contains(MemOps::VITAL) {
                        " | VITAL"
                    } else {
                        ""
                    };
                    writeln!(
                        f,
                        "  r{} = root 0x{:x} 0x{:x} with {}{}{}",
                        idx, region.start, region.end, region.ops, cleanup, vital
                    )?
                }
                RegionKind::Alias(r) => writeln!(
                    f,
                    "  r{} = alias r{} 0x{:x} 0x{:x}",
                    idx, r.idx, region.start, region.end
                )?,
                RegionKind::Carve(r) => writeln!(
                    f,
                    "  r{} = carve r{} 0x{:x} 0x{:x}",
                    idx, r.idx, region.start, region.end
                )?,
            }
            idx += 1;
        }

        for domain in &self.domains.store {
            write!(f, "  d{} = domain {{ ", domain.id)?;
            display_capas(f, &domain.capa)?;
            write!(f, "}} with ")?;
            display_permissions(f, domain.permissions)?;
            writeln!(f, "")?;
            idx += 1;
        }
        writeln!(f, "}}")?;

        Ok(())
    }
}

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ————————————————————————————————— Tests —————————————————————————————————— //

#[cfg(test)]
mod tests {}
