#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
#[repr(usize)]
pub enum PermissionIndex {
    MonitorInterface = 0,
    AllowedTraps = 1,
    AllowedCores = 2,
    MgmtRead16 = 3,
    MgmtWrite16 = 4,
    MgmtRead32 = 5,
    MgmtWrite32 = 6,
    MgmtRead64 = 7,
    MgmtWrite64 = 8,
    MgmtReadNat = 9,
    MgmtWriteNat = 10,
    MgmtReadGp = 11,
    MgmtWriteGp = 12,
}

impl PermissionIndex {
    pub const fn size() -> usize {
        return PermissionIndex::MgmtWriteGp as usize + 1;
    }

    pub fn from_usize(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::MonitorInterface),
            1 => Some(Self::AllowedTraps),
            2 => Some(Self::AllowedCores),
            3 => Some(Self::MgmtRead16),
            4 => Some(Self::MgmtWrite16),
            5 => Some(Self::MgmtRead32),
            6 => Some(Self::MgmtWrite32),
            7 => Some(Self::MgmtRead64),
            8 => Some(Self::MgmtWrite64),
            9 => Some(Self::MgmtReadNat),
            10 => Some(Self::MgmtWriteNat),
            11 => Some(Self::MgmtReadGp),
            12 => Some(Self::MgmtWriteGp),
            _ => None,
        }
    }
}

#[rustfmt::skip]
pub mod monitor_inter_perm {
    pub const SPAWN:     u64 = 1 << 0;
    pub const SEND:      u64 = 1 << 1;
    pub const DUPLICATE: u64 = 1 << 2;
    pub const ALIAS:     u64 = 1 << 3;
    pub const CARVE:     u64 = 1 << 4;

    /// All possible permissions
    pub const ALL:  u64 = SPAWN | SEND | DUPLICATE | ALIAS | CARVE;
    /// None of the existing permissions
    pub const NONE: u64 = 0;
}

pub mod core_bits {
    /// No core.
    pub const NONE: u64 = 0;

    /// All cores.
    pub const ALL: u64 = !(NONE);
}

pub mod trap_bits {
    /// No trap can be handled by the domain.
    pub const NONE: u64 = 0;

    /// All traps can be handled by the domain.
    pub const ALL: u64 = !(NONE);
}

pub struct Permissions {
    pub perm: [u64; PermissionIndex::size()],
}

pub const DEFAULT: Permissions = Permissions {
    perm: [0; PermissionIndex::size()],
};
