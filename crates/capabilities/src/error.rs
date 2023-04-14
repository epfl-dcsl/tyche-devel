//! Errors for capabilities

use core::cmp::PartialEq;
use core::convert::{From, Into};

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(usize)]
pub enum ErrorCode {
    NonResource = 0,
    NonRevocation = 1,
    IncreasingAccessRights = 2,
    NonNullChild = 3,
    NullCapa = 4,
    OutOfBound = 5,
    AllocationError = 6,
    MemoryRegionOutOfBounds = 7,
    AlreadyOwned = 8,
    NotOwnedCapability = 9,
    WrongOwnership = 10,
    MalformedRegion = 11,
    WrongCPUState = 12,
    InvalidDomainCreate = 13,
    CreateOnNewCapa = 14,
    InvalidLocalCapa = 15,
    InvalidSeal = 16,
    InvalidTransfer = 17,
    InvalidShareGrant = 18,
    InvalidRevocation = 19,
    NotADomain = 20,
    NotARegion = 21,
    NotACpu = 22,
    InvalidTransition = 23,
    WrongAccessType = 24,
    ZombieCapaUsed = 25,
    TODO = 26,
    Debug = 27,
    Unexpected = 28,
}

impl ErrorCode {
    pub fn as_err<T, B>(self) -> Result<T, Error<B>> {
        Err(Error::Capability(self))
    }

    pub fn wrap<B>(self) -> Error<B> {
        Error::Capability(self)
    }
}

#[derive(Debug)]
pub enum Error<E> {
    Capability(ErrorCode),
    Backend(E),
}

impl<E> Error<E> {
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Capability(code) => *code,
            Error::Backend(_) => ErrorCode::Debug,
        }
    }
}

impl<E> From<E> for Error<E> {
    fn from(value: E) -> Self {
        Self::Backend(value.into())
    }
}
