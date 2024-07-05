use crate::{permission, CapaError};

pub const CACHE_SIZE: usize = 64;

/// Simple cache implementation.
/// Marks dirty values that need to be flushed.
#[derive(Debug)]
pub struct Cache<const N: usize> {
    pub bitmap: u64,
}

impl<const N: usize> Cache<N> {
    pub fn is_on(&self, idx: usize) -> bool {
        if idx >= N {
            return false;
        }
        self.bitmap & (1 << idx) != 0
    }
    pub fn set(&mut self, idx: usize) -> bool {
        if idx >= N {
            return false;
        }
        self.bitmap |= 1 << idx;
        return true;
    }
    pub fn clear(&mut self, idx: usize) -> bool {
        if idx >= N {
            return false;
        }
        self.bitmap &= !(1 << idx);
        return true;
    }
    #[allow(dead_code)]
    pub fn clear_all(&mut self) {
        self.bitmap = 0;
    }
}

/// The groups of registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum RegisterGroup {
    Reg16 = 0,
    Reg32 = 1,
    Reg64 = 2,
    RegNat = 3,
    RegGp = 4,
}

impl RegisterGroup {
    pub fn from_usize(v: usize) -> Self {
        match v {
            0 => Self::Reg16,
            1 => Self::Reg32,
            2 => Self::Reg64,
            3 => Self::RegNat,
            4 => Self::RegGp,
            _ => panic!("Invalid"),
        }
    }
    pub const fn size() -> usize {
        return Self::RegGp as usize + 1;
    }

    pub fn to_permissions(&self) -> (permission::PermissionIndex, permission::PermissionIndex) {
        match &self {
            Self::Reg16 => (
                permission::PermissionIndex::MgmtRead16,
                permission::PermissionIndex::MgmtWrite16,
            ),
            Self::Reg32 => (
                permission::PermissionIndex::MgmtRead32,
                permission::PermissionIndex::MgmtWrite32,
            ),
            Self::Reg64 => (
                permission::PermissionIndex::MgmtRead64,
                permission::PermissionIndex::MgmtWrite64,
            ),
            Self::RegNat => (
                permission::PermissionIndex::MgmtReadNat,
                permission::PermissionIndex::MgmtWriteNat,
            ),
            Self::RegGp => (
                permission::PermissionIndex::MgmtReadGp,
                permission::PermissionIndex::MgmtWriteGp,
            ),
        }
    }
}

/// State for a given size of registers.
pub struct RegisterState<const N: usize> {
    pub dirty: Cache<N>,
    pub values: [usize; N],
}

impl<const N: usize> RegisterState<N> {
    pub const fn new() -> Self {
        RegisterState {
            dirty: Cache { bitmap: 0 },
            values: [0; N],
        }
    }
    pub fn is_valid(&self, idx: usize) -> bool {
        if idx >= N {
            return false;
        }
        return true;
    }

    pub fn set(&mut self, idx: usize, value: usize) -> Result<(), CapaError> {
        if !self.is_valid(idx) {
            return Err(CapaError::InvalidOperation);
        }
        self.values[idx] = value;
        self.dirty.set(idx);
        return Ok(());
    }

    pub fn get(&self, idx: usize) -> Result<usize, CapaError> {
        if !self.is_valid(idx) {
            return Err(CapaError::InvalidOperation);
        }
        return Ok(self.values[idx]);
    }

    pub fn flush<F>(&mut self, mut callback: F)
    where
        F: FnMut(usize, usize),
    {
        for i in 0..N {
            if !self.dirty.is_on(i) {
                continue;
            }
            callback(i, self.values[i]);
            self.dirty.clear(i);
        }
    }
}

pub struct RegisterContext<
    const N16: usize,
    const N32: usize,
    const N64: usize,
    const NNAT: usize,
    const NGP: usize,
> {
    /// Quick marker for dirty values inside each  register group.
    pub dirty: Cache<{ RegisterGroup::size() }>,
    /// 16-bits registers.
    pub state_16: RegisterState<N16>,
    /// 32-bits registers.
    pub state_32: RegisterState<N32>,
    /// 64-bits registers.
    pub state_64: RegisterState<N64>,
    /// Nat registers.
    pub state_nat: RegisterState<NNAT>,
    /// General-purpose (GP) registers.
    pub state_gp: RegisterState<NGP>,
}

impl<const N16: usize, const N32: usize, const N64: usize, const NNAT: usize, const NGP: usize>
    RegisterContext<N16, N32, N64, NNAT, NGP>
{
    pub fn reset(&mut self) {
        *self = RegisterContext {
            dirty: Cache { bitmap: 0 },
            state_16: RegisterState::new(),
            state_32: RegisterState::new(),
            state_64: RegisterState::new(),
            state_nat: RegisterState::new(),
            state_gp: RegisterState::new(),
        }
    }
    pub fn set(&mut self, group: RegisterGroup, idx: usize, value: usize) -> Result<(), CapaError> {
        match group {
            RegisterGroup::Reg16 => self.state_16.set(idx, value)?,
            RegisterGroup::Reg32 => self.state_32.set(idx, value)?,
            RegisterGroup::Reg64 => self.state_64.set(idx, value)?,
            RegisterGroup::RegNat => self.state_nat.set(idx, value)?,
            RegisterGroup::RegGp => self.state_gp.set(idx, value)?,
        }
        if !self.dirty.set(group as usize) {
            return Err(CapaError::InvalidOperation);
        }
        return Ok(());
    }

    pub fn get(&self, group: RegisterGroup, idx: usize) -> Result<usize, CapaError> {
        let res = match group {
            RegisterGroup::Reg16 => self.state_16.get(idx)?,
            RegisterGroup::Reg32 => self.state_32.get(idx)?,
            RegisterGroup::Reg64 => self.state_64.get(idx)?,
            RegisterGroup::RegNat => self.state_nat.get(idx)?,
            RegisterGroup::RegGp => self.state_gp.get(idx)?,
        };
        return Ok(res);
    }

    pub fn clear(&mut self, group: RegisterGroup, idx: usize) {
        match group {
            RegisterGroup::Reg16 => self.state_16.dirty.clear(idx),
            RegisterGroup::Reg32 => self.state_32.dirty.clear(idx),
            RegisterGroup::Reg64 => self.state_64.dirty.clear(idx),
            RegisterGroup::RegNat => self.state_nat.dirty.clear(idx),
            RegisterGroup::RegGp => self.state_gp.dirty.clear(idx),
        };
    }

    pub fn flush<F>(&mut self, mut callback: F)
    where
        F: FnMut(RegisterGroup, usize, usize),
    {
        for i in 0..RegisterGroup::size() {
            if !self.dirty.is_on(i) {
                continue;
            }
            let g = RegisterGroup::from_usize(i);
            let fg = |idx: usize, value: usize| callback(g, idx, value);

            match g {
                RegisterGroup::Reg16 => self.state_16.flush(fg),
                RegisterGroup::Reg32 => self.state_32.flush(fg),
                RegisterGroup::Reg64 => self.state_64.flush(fg),
                RegisterGroup::RegNat => self.state_nat.flush(fg),
                RegisterGroup::RegGp => self.state_gp.flush(fg),
            }
            self.dirty.clear(i);
        }
    }
}
