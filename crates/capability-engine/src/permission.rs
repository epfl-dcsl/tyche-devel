#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
#[repr(u64)]
pub enum PermissionIndex {
    MonitorInterface = 0,
    // 256 possible values
    AllowedTraps = 1,
    AllowedTraps1 = 2,
    AllowedTraps2 = 3,
    AllowedTraps3 = 4,
    AllowedCores = 5,
    MgmtRead16 = 6,
    MgmtWrite16 = 7,
    MgmtRead32 = 8,
    MgmtWrite32 = 9,
    MgmtRead64 = 10,
    MgmtWrite64 = 11,
    MgmtReadNat = 12,
    MgmtWriteNat = 13,
    MgmtReadGp = 14,
    MgmtWriteGp = 15,
}

impl PermissionIndex {
    pub const fn size() -> usize {
        return PermissionIndex::MgmtWriteGp as usize + 1;
    }

    pub fn from_usize(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::MonitorInterface),
            1 => Some(Self::AllowedTraps),
            2 => Some(Self::AllowedTraps1),
            3 => Some(Self::AllowedTraps2),
            4 => Some(Self::AllowedTraps3),
            5 => Some(Self::AllowedCores),
            6 => Some(Self::MgmtRead16),
            7 => Some(Self::MgmtWrite16),
            8 => Some(Self::MgmtRead32),
            9 => Some(Self::MgmtWrite32),
            10 => Some(Self::MgmtRead64),
            11 => Some(Self::MgmtWrite64),
            12 => Some(Self::MgmtReadNat),
            13 => Some(Self::MgmtWriteNat),
            14 => Some(Self::MgmtReadGp),
            15 => Some(Self::MgmtWriteGp),
            _ => None,
        }
    }

    pub fn nb_entries_per_bitmap() -> u64 {
        64
    }
}

#[rustfmt::skip]
pub mod monitor_inter_perm {
    pub const SPAWN:     u64 = 1 << 0;
    pub const SEND:      u64 = 1 << 1;
    pub const DUPLICATE: u64 = 1 << 2;
    pub const ALIAS:     u64 = 1 << 3;
    pub const CARVE:     u64 = 1 << 4;
    pub const CPUID:     u64 = 1 << 5;

    /// All possible permissions
    pub const ALL:  u64 = SPAWN | SEND | DUPLICATE | ALIAS | CARVE | CPUID;
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

    /// Trap bits without exceptions. Use only for first bitmap.
    pub const ALL_NO_EXCEPT: u64 = !((1 << 32) - 1);
}

pub struct Permissions {
    pub freezed: bool,
    pub perm: [u64; PermissionIndex::size()],
}

pub const DEFAULT: Permissions = Permissions {
    freezed: false,
    perm: [0; PermissionIndex::size()],
};
