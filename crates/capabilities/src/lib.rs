//! Generic Capability Model
#![cfg_attr(not(test), no_std)]

pub mod access;
pub mod backend;
pub mod context;
pub mod cpu;
pub mod domain;
pub mod error;
pub mod memory;

#[cfg(test)]
mod tests;

use core::cell::{Ref, RefMut};

use arena::{ArenaItem, Handle, TypedArena};
use backend::Backend;
use cpu::CPU;
use domain::{Domain, DomainAccess, OwnedCapability, SealedStatus, CAPAS_PER_DOMAIN};

use crate::access::AccessRights;
use crate::error::{Error, ErrorCode};

// —————————————————————————— Constant Pool Sizes ——————————————————————————— //
pub const DOMAIN_POOL_SIZE: usize = 100;
pub const MEMORY_POOL_SIZE: usize = 100;
pub const CPU_POOL_SIZE: usize = 100;
pub const CAPA_POOL_SIZE: usize = 100;

/// Capability Type: resource or revocation.
///
/// Resource maps to the ability to access a resource.
/// Revocation maps to the ability to revoke capabilities.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum CapabilityType {
    Resource,
    Revocation,
}

/// Represents ownership of capability.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Ownership {
    Empty,
    Zombie,
    Domain(usize, usize), // (domain, local_idx)
}

#[derive(Debug)]
pub struct Capability<T>
where
    T: Object + 'static,
{
    /// Owner of the resource.
    pub owner: Ownership,
    /// Resource or revocation.
    pub capa_type: CapabilityType,
    /// Access rights for the capability.
    pub access: T::Access,
    /// The handle to the object
    pub handle: Handle<T>,
    /// Left child.
    pub left: Handle<Capability<T>>,
    /// Right child.
    pub right: Handle<Capability<T>>,
}

pub trait Object: Sized {
    type Access: AccessRights + Copy;
    fn from_bits(arg1: usize, arg2: usize, arg3: usize) -> Self::Access;
    fn incr_ref(&mut self, pool: &impl Pool<Self>, capa: &Capability<Self>);
    fn decr_ref(&mut self, pool: &impl Pool<Self>, capa: &Capability<Self>);
    fn get_ref(&self, pool: &impl Pool<Self>, capa: &Capability<Self>) -> usize;
    fn create_from(
        pool: &impl Pool<Self>,
        capa: &Capability<Self>,
        op: &Self::Access,
    ) -> Result<Handle<Capability<Self>>, ErrorCode>;
}

impl<T> Capability<T>
where
    T: Object,
{
    pub fn duplicate<P>(
        &mut self,
        op1: T::Access,
        op2: T::Access,
        pool: &P,
    ) -> Result<(Handle<Capability<T>>, Handle<Capability<T>>), Error<<P::B as Backend>::Error>>
    where
        P: Pool<T>,
    {
        // Only owned capabilities can be duplicated.
        if self.owner == Ownership::Empty {
            return ErrorCode::NotOwnedCapability.as_err();
        }
        // Invalid split of revocation handle.
        if self.capa_type == CapabilityType::Revocation {
            return ErrorCode::NonResource.as_err();
        }
        // Attempting to increase access rights.
        if !self.access.is_valid_dup(&op1, &op2) {
            return ErrorCode::IncreasingAccessRights.as_err();
        }
        // Malformed tree, it is not a revocation but has children.
        if !self.left.is_null() || !self.right.is_null() {
            return ErrorCode::NonNullChild.as_err();
        }

        self.left = T::create_from(pool, self, &op1).map_err(|e| Error::Capability(e))?;
        // If this one fails, we need to undo left as well.
        match T::create_from(pool, self, &op2) {
            Ok(r) => self.right = r,
            Err(e) => {
                if !self.left.is_null() {
                    Capability::<T>::destroy(Handle::new_unchecked(self.left.idx()), pool)?;
                    self.left = Handle::null();
                }
                return e.as_err();
            }
        };
        // Revert everything, otherwise we end up with multiple handles.
        match self.into_revok(pool) {
            Ok(_) => {}
            Err(e) => {
                if !self.left.is_null() {
                    Capability::<T>::destroy(Handle::new_unchecked(self.left.idx()), pool)?;
                    self.left = Handle::null();
                }
                if !self.right.is_null() {
                    Capability::<T>::destroy(Handle::new_unchecked(self.right.idx()), pool)?;
                    self.right = Handle::null();
                }
                return Err(e);
            }
        };
        pool.backend_duplicate(self)?;
        Ok((self.left, self.right))
    }

    pub fn revoke<P>(&mut self, pool: &P) -> Result<(), Error<<P::B as Backend>::Error>>
    where
        P: Pool<T>,
    {
        // Only owned capabilities can be duplicated.
        if self.owner == Ownership::Empty {
            return ErrorCode::NotOwnedCapability.as_err();
        }
        // The capability is not a revocation one.
        if self.capa_type != CapabilityType::Revocation {
            return ErrorCode::NonRevocation.as_err();
        }

        // Clean the left and the right handles (cascading revocation)
        if !self.left.is_null() {
            {
                let mut left = pool.get_capa_mut(Handle::new_unchecked(self.left.idx()));
                if left.capa_type != CapabilityType::Resource {
                    left.revoke(pool)?;
                }
            }
        }

        if !self.right.is_null() {
            {
                let mut right = pool.get_capa_mut(Handle::new_unchecked(self.right.idx()));
                if right.capa_type != CapabilityType::Resource {
                    right.revoke(pool)?;
                }
            }
        }

        // At this point, root is still revocation, left and right should be resources.
        pool.backend_revoke(self)?;
        if !self.left.is_null() {
            Capability::<T>::destroy(self.left, pool)?;
            self.left = Handle::null();
        }
        if !self.right.is_null() {
            Capability::<T>::destroy(self.right, pool)?;
            self.right = Handle::null();
        }

        self.into_resource(pool)?;
        Ok(())
    }

    pub fn into_revok<P>(&mut self, pool: &P) -> Result<(), Error<<P::B as Backend>::Error>>
    where
        P: Pool<T>,
    {
        self.pause(pool)?;
        self.capa_type = CapabilityType::Revocation;
        Ok(())
    }

    pub fn into_resource<P>(&mut self, pool: &P) -> Result<(), Error<<P::B as Backend>::Error>>
    where
        P: Pool<T>,
    {
        if self.capa_type != CapabilityType::Revocation {
            return ErrorCode::NonRevocation.as_err();
        }
        self.capa_type = CapabilityType::Resource;
        {
            let mut obj = pool.get_mut(self.handle);
            obj.incr_ref(pool, self);
            //obj.install(pool, self)?;
        }
        // Backend call to reinstall the capability.
        pool.backend_apply(self)?;
        Ok(())
    }

    /// Pause a capability decrements the reference and uninstalls the corresponding ability.
    /// It does not deallocate the capability itself though.
    /// The function is used by into_revok and during revocation.
    pub fn pause<P>(&mut self, pool: &P) -> Result<(), Error<<P::B as Backend>::Error>>
    where
        P: Pool<T>,
    {
        // Only owned capabilities can be destroyed.
        if self.owner == Ownership::Empty {
            return ErrorCode::NotOwnedCapability.as_err();
        }
        // Only resource capa can be destroyed.
        if self.capa_type != CapabilityType::Resource {
            return ErrorCode::NonResource.as_err();
        }
        {
            let mut obj = pool.get_mut(self.handle);
            obj.decr_ref(pool, self);
        }
        Ok(())
    }

    /// Destroy a capability.
    /// It pauses it and then deallocates it from the pool and the domain's pool.
    pub fn destroy<P>(
        capa: Handle<Capability<T>>,
        pool: &P,
    ) -> Result<(), Error<<P::B as Backend>::Error>>
    where
        P: Pool<T>,
    {
        {
            let mut capa = pool.get_capa_mut(capa);
            capa.pause(pool)?;
        }
        pool.remove_owner(capa).map_err(|e| Error::Capability(e))?;
        pool.free_capa(capa);
        Ok(())
    }

    pub fn get_local_idx<E>(&self) -> Result<usize, Error<E>> {
        match self.owner {
            Ownership::Domain(_, idx) => Ok(idx),
            _ => ErrorCode::NotOwnedCapability.as_err(),
        }
    }

    pub fn get_owner<E, B: Backend>(&self) -> Result<Handle<Domain<B>>, Error<E>> {
        match self.owner {
            Ownership::Domain(dom, _idx) => Ok(Handle::new_unchecked(dom)),
            Ownership::Zombie => ErrorCode::ZombieCapaUsed.as_err(),
            _ => ErrorCode::NotOwnedCapability.as_err(),
        }
    }
}

// ——————————————————————— Arena Item Implementation ———————————————————————— //
impl<T> ArenaItem for Capability<T>
where
    T: Object,
{
    type Error = ErrorCode;
    const OUT_OF_BOUND_ERROR: Self::Error = ErrorCode::OutOfBound;
    const ALLOCATION_ERROR: Self::Error = ErrorCode::AllocationError;
}

// ————————————————————————— Object Pool and State —————————————————————————— //

/// The object pool, backing up all objects allocations.
pub struct OPool<B>
where
    B: Backend + 'static,
{
    pub domains: TypedArena<Domain<B>, DOMAIN_POOL_SIZE>, // TODO: make generic over size
    pub regions: TypedArena<memory::MemoryRegion, MEMORY_POOL_SIZE>,
    pub cpus: TypedArena<cpu::CPU<B>, CPU_POOL_SIZE>,
    pub domain_capas: TypedArena<Capability<Domain<B>>, CAPA_POOL_SIZE>,
    pub region_capas: TypedArena<Capability<memory::MemoryRegion>, CAPA_POOL_SIZE>,
    pub cpu_capas: TypedArena<Capability<cpu::CPU<B>>, CAPA_POOL_SIZE>,
}

pub struct State<'a, B>
where
    B: Backend + Sized + 'a + 'static,
{
    pub backend: B,
    pub pools: &'a OPool<B>,
}

/// The Pool trait, the main object pool implement it for each type it contains.
pub trait Pool<T: Object> {
    type B: Backend;
    // Object methods.
    fn get(&self, handle: Handle<T>) -> Ref<T>;
    fn get_mut(&self, handle: Handle<T>) -> RefMut<T>;
    fn allocate(&self) -> Result<Handle<T>, ErrorCode>;
    fn free(&self, handle: Handle<T>);
    // Capa methods.
    fn get_capa(&self, handle: Handle<Capability<T>>) -> Ref<Capability<T>>;
    fn get_capa_mut(&self, handle: Handle<Capability<T>>) -> RefMut<Capability<T>>;
    fn allocate_capa(&self) -> Result<Handle<Capability<T>>, ErrorCode>;
    fn free_capa(&self, handle: Handle<Capability<T>>);
    // Register capability.
    fn set_owner_capa(
        &self,
        capa: Handle<Capability<T>>,
        domain: Handle<Domain<Self::B>>,
    ) -> Result<(), ErrorCode>;
    fn remove_owner(&self, capa: Handle<Capability<T>>) -> Result<(), ErrorCode>;
    fn into_zombie_owner(&self, capa: Handle<Capability<T>>) -> Result<(), ErrorCode> {
        let mut capa = self.get_capa_mut(capa);
        if let Ownership::Domain(_, _) = capa.owner {
            capa.owner = Ownership::Zombie;
            return Ok(());
        }
        return Err(ErrorCode::WrongOwnership);
    }
    fn transfer(
        &self,
        capa: Handle<Capability<T>>,
        domain: Handle<Domain<Self::B>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        let previous = self.get_capa(capa).get_owner()?;
        if previous.idx() == domain.idx() {
            return Ok(());
        }
        self.backend_unapply(capa)?;
        self.remove_owner(capa).map_err(|e| e.wrap())?;
        match self.set_owner_capa(capa, domain) {
            Ok(()) => {
                let capa = self.get_capa(capa);
                self.backend_apply(&capa)?;
                Ok(())
            }
            // Something went wrong, try to reestablish the original owner.
            Err(e) => {
                self.set_owner_capa(capa, previous).map_err(|e| e.wrap())?;
                return e.as_err();
            }
        }
    }

    // Backend calls
    /// Called at the end of a duplicate.
    fn backend_duplicate(
        &self,
        orig: &Capability<T>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>>;
    /// Called at the end of a revoke.
    fn backend_revoke(
        &self,
        orig: &Capability<T>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>>;
    /// Called when we go from revoke to resource or when we transfer (receive).
    fn backend_apply(&self, capa: &Capability<T>)
        -> Result<(), Error<<Self::B as Backend>::Error>>;
    /// Called when the capability is revoked or transfered (send).
    fn backend_unapply(
        &self,
        capa: Handle<Capability<T>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>>;
}

// ———————————————————— Pool Implementation for Domains ————————————————————— //

impl<Back: Backend + Sized> Pool<Domain<Back>> for State<'_, Back> {
    type B = Back;

    fn get(&self, handle: Handle<Domain<Self::B>>) -> Ref<Domain<Self::B>> {
        self.pools.domains.get(handle)
    }

    fn get_mut(&self, handle: Handle<Domain<Self::B>>) -> RefMut<Domain<Self::B>> {
        self.pools.domains.get_mut(handle)
    }

    fn allocate(&self) -> Result<Handle<Domain<Self::B>>, ErrorCode> {
        self.pools.domains.allocate()
    }

    fn free(&self, handle: Handle<Domain<Self::B>>) {
        self.pools.domains.free(handle);
    }

    fn get_capa(
        &self,
        handle: Handle<Capability<Domain<Self::B>>>,
    ) -> Ref<Capability<Domain<Self::B>>> {
        self.pools.domain_capas.get(handle)
    }

    fn get_capa_mut(
        &self,
        handle: Handle<Capability<Domain<Self::B>>>,
    ) -> RefMut<Capability<Domain<Self::B>>> {
        self.pools.domain_capas.get_mut(handle)
    }

    fn allocate_capa(&self) -> Result<Handle<Capability<Domain<Self::B>>>, ErrorCode> {
        self.pools.domain_capas.allocate()
    }

    fn free_capa(&self, handle: Handle<Capability<Domain<Self::B>>>) {
        self.pools.domain_capas.free(handle);
    }

    fn set_owner_capa(
        &self,
        capa: Handle<Capability<Domain<Self::B>>>,
        domain: Handle<Domain<Self::B>>,
    ) -> Result<(), ErrorCode> {
        {
            let capa = self.get_capa(capa);
            if capa.owner != Ownership::Empty {
                return Err(ErrorCode::AlreadyOwned);
            }
        }
        // Create an owner in the domain.
        let dom = self.pools.domains.get(domain);
        let owned_handle = dom.owned.allocate()?;
        let mut owned = dom.owned.get_mut(owned_handle);
        *owned = OwnedCapability::Domain(capa);
        // Register it in the capa.
        {
            let mut capa = self.get_capa_mut(capa);
            capa.owner = Ownership::Domain(domain.idx(), owned_handle.idx());
        }
        Ok(())
    }

    fn remove_owner(&self, capa: Handle<Capability<Domain<Self::B>>>) -> Result<(), ErrorCode> {
        let capa_handle = capa;
        let mut capa = self.get_capa_mut(capa);
        match capa.owner {
            Ownership::Domain(dom, idx) => {
                let domain = self.pools.domains.get(Handle::new_unchecked(dom));
                domain.remove_capa(idx, OwnedCapability::Domain(capa_handle))?;
            }
            Ownership::Zombie => {}
            Ownership::Empty => {
                return Err(ErrorCode::NotOwnedCapability);
            }
        };
        capa.owner = Ownership::Empty;
        Ok(())
    }

    fn backend_duplicate(
        &self,
        orig: &Capability<Domain<Back>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        // With domain duplicates, we are only interested in create calls.
        // That means if right is unsealed.
        // Anything else, we do not care.
        if orig.right.is_null() {
            return Ok(());
        }

        let left = self.get_capa(orig.left);
        match left.access {
            domain::DomainAccess::Sealed(_, _) => {}
            _ => {
                return Ok(());
            }
        }
        // The left is a sealed capa, we need to update the seal.
        if let Ownership::Domain(_, idx) = left.owner {
            let mut domain = self.get_mut(left.handle);
            if let SealedStatus::Sealed(_) = domain.sealed {
                // Nothing to do.
            } else {
                return Err(ErrorCode::InvalidDomainCreate.wrap());
            }
            // Update the reference to the local sealed capa.
            domain.sealed = SealedStatus::<Self::B>::Sealed(Handle::new_unchecked(idx));
        }

        // Last thing to do is create a domain if right is unsealed, i.e.,
        // if this call was a create.
        let right = self.get_capa(orig.right);
        match right.access {
            DomainAccess::Unsealed(_, _) => {
                self.backend.create_domain(self, &right)?;
            }
            _ => {}
        };
        Ok(())
    }

    fn backend_revoke(
        &self,
        orig: &Capability<Domain<Back>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        // The right cannot be null if it was a sealed capa.
        if orig.right.is_null() {
            return Ok(());
        }

        //Check if we need to free a transition.
        {
            let right = self.get_capa(orig.right);
            if let DomainAccess::Transition(id) = right.access {
                let domain = self.get(right.handle);
                // TODO are we leaking handles? Charly is working on v3 so
                // probably not worth fixing right now.
                let mut ctxt = domain.contexts.get_mut(Handle::new_unchecked(id));
                ctxt.return_context = None;
                domain.contexts.free(Handle::new_unchecked(id));
            }
        }

        if let domain::DomainAccess::Sealed(_, _) = orig.access {
            if let Ownership::Domain(_, idx) = orig.owner {
                // We should reestablish the sealed handle.
                let mut domain = self.get_mut(orig.handle);
                if let domain::SealedStatus::Sealed(_) = domain.sealed {
                    domain.sealed =
                        domain::SealedStatus::<Self::B>::Sealed(Handle::new_unchecked(idx));
                } else {
                    return Err(ErrorCode::InvalidSeal.wrap());
                }
            } else {
                // Something is malformed.
                return Err(ErrorCode::WrongOwnership.wrap());
            }
        }
        self.backend_unapply(orig.right)?;
        Ok(())
    }

    fn backend_apply(
        &self,
        _capa: &Capability<Domain<Self::B>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        //self.backend.install_domain(&self, capa)
        // TODO figure that out.
        Ok(())
    }

    fn backend_unapply(
        &self,
        capa: Handle<Capability<Domain<Self::B>>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        //Perform the cleanup now.
        //TODO the logic here is flawed for some reason.
        let needs_cleanup = {
            let capa = self.get_capa(capa);
            let count = self.get(capa.handle).get_ref(self, &capa);
            match capa.access {
                DomainAccess::Sealed(_, _) => true && count == 1,
                DomainAccess::Unsealed(_, _) => true && count == 1,
                _ => false,
            }
        };
        // Enumerate and zombified the local capas.
        if needs_cleanup {
            let object = {
                let capa = self.get_capa(capa);
                self.get(capa.handle)
            };
            for i in 0..CAPAS_PER_DOMAIN {
                if object.owned.is_allocated(i) {
                    let o = object.owned.get(Handle::new_unchecked(i));
                    match *o {
                        OwnedCapability::Region(h) => {
                            self.backend_unapply(h)?;
                            self.into_zombie_owner(h).map_err(|e| e.wrap())?
                        }
                        OwnedCapability::Domain(h) => {
                            self.backend_unapply(h)?;
                            self.into_zombie_owner(h).map_err(|e| e.wrap())?
                        }
                        OwnedCapability::CPU(h) => {
                            self.backend_unapply(h)?;
                            self.into_zombie_owner(h).map_err(|e| e.wrap())?
                        }
                        _ => {}
                    };
                }
            }
        }
        {
            let capa = self.get_capa(capa);
            self.backend.uninstall_domain(&self, &capa)?;
        }
        let mut needs_free = false;
        {
            let capa = self.get_capa(capa);
            let domain = self.get(capa.handle);
            if domain.get_ref(self, &capa) == 1 {
                needs_free = true;
            }
        }
        if needs_cleanup && needs_free {
            let obj = self.get_capa(capa).handle;
            self.free(obj);
        }
        Ok(())
    }
}

// ————————————————— Pool Implementation for Memory Regions ————————————————— //

impl<Back: Backend + Sized> Pool<memory::MemoryRegion> for State<'_, Back> {
    type B = Back;

    fn get(&self, handle: Handle<memory::MemoryRegion>) -> Ref<memory::MemoryRegion> {
        self.pools.regions.get(handle)
    }
    fn get_mut(&self, handle: Handle<memory::MemoryRegion>) -> RefMut<memory::MemoryRegion> {
        self.pools.regions.get_mut(handle)
    }

    fn allocate(&self) -> Result<Handle<memory::MemoryRegion>, ErrorCode> {
        self.pools.regions.allocate()
    }

    fn free(&self, handle: Handle<memory::MemoryRegion>) {
        self.pools.regions.free(handle);
    }

    fn get_capa(
        &self,
        handle: Handle<Capability<memory::MemoryRegion>>,
    ) -> Ref<Capability<memory::MemoryRegion>> {
        self.pools.region_capas.get(handle)
    }

    fn get_capa_mut(
        &self,
        handle: Handle<Capability<memory::MemoryRegion>>,
    ) -> RefMut<Capability<memory::MemoryRegion>> {
        self.pools.region_capas.get_mut(handle)
    }

    fn allocate_capa(&self) -> Result<Handle<Capability<memory::MemoryRegion>>, ErrorCode> {
        self.pools.region_capas.allocate()
    }

    fn free_capa(&self, handle: Handle<Capability<memory::MemoryRegion>>) {
        self.pools.region_capas.free(handle);
    }

    fn set_owner_capa(
        &self,
        capa: Handle<Capability<memory::MemoryRegion>>,
        domain: Handle<Domain<Back>>,
    ) -> Result<(), ErrorCode> {
        {
            let capa = self.get_capa(capa);
            if capa.owner != Ownership::Empty {
                return Err(ErrorCode::AlreadyOwned);
            }
        }
        // Create an owner in the domain.
        let dom = self.pools.domains.get(domain);
        let owned_handle = dom.owned.allocate()?;
        let mut owned = dom.owned.get_mut(owned_handle);
        *owned = OwnedCapability::Region(capa);
        // Register it in the capa.
        {
            let mut capa = self.get_capa_mut(capa);
            capa.owner = Ownership::Domain(domain.idx(), owned_handle.idx());
        }
        Ok(())
    }

    fn remove_owner(
        &self,
        capa: Handle<Capability<memory::MemoryRegion>>,
    ) -> Result<(), ErrorCode> {
        let capa_handle = capa;
        let mut capa = self.get_capa_mut(capa);
        match capa.owner {
            Ownership::Domain(dom, idx) => {
                let domain = self.pools.domains.get(Handle::new_unchecked(dom));
                domain.remove_capa(idx, OwnedCapability::Region(capa_handle))?;
            }
            Ownership::Zombie => {}
            Ownership::Empty => {
                return Err(ErrorCode::NotOwnedCapability);
            }
        };
        capa.owner = Ownership::Empty;
        Ok(())
    }

    fn backend_duplicate(
        &self,
        _orig: &Capability<memory::MemoryRegion>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        //TODO optimize that call with one from the backend.
        Ok(())
    }

    fn backend_revoke(
        &self,
        _orig: &Capability<memory::MemoryRegion>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        // TODO optimize
        Ok(())
    }

    fn backend_apply(
        &self,
        capa: &Capability<memory::MemoryRegion>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        let mut region = self.get_mut(capa.handle);
        region.merge(1, self, capa);
        self.backend.install_region(&self, capa)
    }

    fn backend_unapply(
        &self,
        capa: Handle<Capability<memory::MemoryRegion>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        let capa = self.get_capa(capa);
        let mut region = self.get_mut(capa.handle);
        region.merge(0, self, &capa);
        self.backend.uninstall_region(&self, &capa)
    }
}

// —————————————————————— Pool Implementation for CPUs —————————————————————— //

impl<Back: Backend + Sized> Pool<CPU<Back>> for State<'_, Back> {
    type B = Back;

    fn get(&self, handle: Handle<CPU<Self::B>>) -> Ref<CPU<Self::B>> {
        self.pools.cpus.get(handle)
    }

    fn get_mut(&self, handle: Handle<CPU<Back>>) -> RefMut<CPU<Back>> {
        self.pools.cpus.get_mut(handle)
    }

    fn allocate(&self) -> Result<Handle<CPU<Back>>, ErrorCode> {
        self.pools.cpus.allocate()
    }

    fn free(&self, handle: Handle<CPU<Back>>) {
        self.pools.cpus.free(handle);
    }

    fn get_capa(&self, handle: Handle<Capability<CPU<Back>>>) -> Ref<Capability<CPU<Back>>> {
        self.pools.cpu_capas.get(handle)
    }

    fn get_capa_mut(&self, handle: Handle<Capability<CPU<Back>>>) -> RefMut<Capability<CPU<Back>>> {
        self.pools.cpu_capas.get_mut(handle)
    }
    fn allocate_capa(&self) -> Result<Handle<Capability<CPU<Back>>>, ErrorCode> {
        self.pools.cpu_capas.allocate()
    }

    fn free_capa(&self, handle: Handle<Capability<CPU<Back>>>) {
        self.pools.cpu_capas.free(handle);
    }

    fn set_owner_capa(
        &self,
        capa: Handle<Capability<CPU<Back>>>,
        domain: Handle<Domain<Back>>,
    ) -> Result<(), ErrorCode> {
        {
            let capa = self.get_capa(capa);
            if capa.owner != Ownership::Empty {
                return Err(ErrorCode::AlreadyOwned);
            }
        }
        // Create an owner in the domain.
        let dom = self.pools.domains.get(domain);
        let owned_handle = dom.owned.allocate()?;
        let mut owned = dom.owned.get_mut(owned_handle);
        *owned = OwnedCapability::CPU(capa);
        // Register it in the capa.
        {
            let mut capa = self.get_capa_mut(capa);
            capa.owner = Ownership::Domain(domain.idx(), owned_handle.idx());
        }
        Ok(())
    }

    fn remove_owner(&self, capa: Handle<Capability<CPU<Back>>>) -> Result<(), ErrorCode> {
        let capa_handle = capa;
        let mut capa = self.get_capa_mut(capa);
        match capa.owner {
            Ownership::Domain(dom, idx) => {
                let domain = self.pools.domains.get(Handle::new_unchecked(dom));
                domain.remove_capa(idx, OwnedCapability::CPU(capa_handle))?;
            }
            Ownership::Zombie => {}
            Ownership::Empty => {
                return Err(ErrorCode::NotOwnedCapability);
            }
        };
        capa.owner = Ownership::Empty;
        Ok(())
    }

    fn backend_duplicate(
        &self,
        _orig: &Capability<CPU<Back>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        // Nothing to do?
        Ok(())
    }
    fn backend_revoke(
        &self,
        _orig: &Capability<CPU<Back>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        // TODO optimize
        Ok(())
    }
    fn backend_apply(
        &self,
        capa: &Capability<CPU<Back>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        self.backend.install_cpu(&self, capa)
    }

    fn backend_unapply(
        &self,
        capa: Handle<Capability<CPU<Back>>>,
    ) -> Result<(), Error<<Self::B as Backend>::Error>> {
        let capa = self.get_capa(capa);
        self.backend.uninstall_cpu(&self, &capa)
    }
}
