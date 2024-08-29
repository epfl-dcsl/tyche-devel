use core::cmp::min;
use core::fmt::Display;
use core::mem;
use core::num::TryFromIntError;

use capa_engine::CapaError;

const DATA_POOL_ENTRY_COUNT: usize = 10;
pub const DATA_POOL_ENTRY_BYTES: usize = 256;
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct DataTransferPoolHandle {
    handle: u8,
}

impl DataTransferPoolHandle {
    pub const fn invalid() -> Self {
        DataTransferPoolHandle { handle: 0 }
    }
    fn to_idx(&self) -> usize {
        (self.handle - 1) as usize
    }

    fn from_idx(idx: usize) -> Result<Self, TryFromIntError> {
        Ok(Self {
            handle: (idx + 1).try_into()?,
        })
    }

    pub fn serialize(&self) -> u8 {
        self.handle
    }

    pub fn deserialize(raw: usize) -> Result<Self, CapaError> {
        let v = Self {
            handle: raw
                .try_into()
                .map_err(|_| CapaError::CouldNotDeserializeInfo)?,
        };
        if v == Self::invalid() {
            return Err(CapaError::CouldNotDeserializeInfo);
        }
        Ok(v)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum DataTransferPoolEntryState {
    UNUSED,
    /// domain sends data in chunks
    ReceivingFromDomain,
    /// domain sent all data, ready for consumption by tyche
    FromDomainReady,
    /// Data from tyche that is getting polled by domain
    SendingToDomain,
}

impl Display for DataTransferPoolEntryState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                DataTransferPoolEntryState::UNUSED => "UNUSED",
                DataTransferPoolEntryState::ReceivingFromDomain => "ReceivingFromDomain",
                DataTransferPoolEntryState::FromDomainReady => "FromDomainReady",
                DataTransferPoolEntryState::SendingToDomain => "SendingToDomain",
            }
        )
    }
}

pub enum DataPoolDirection<'a> {
    ToDomain(&'a [u8]),
    FromDomain,
}

#[derive(Clone, Copy)]
pub struct DataPoolEntry {
    data: [u8; DATA_POOL_ENTRY_BYTES],
    /// inclusive start of valid data in `data`
    start_idx: usize,
    /// exclusive end of valid data in `data`
    end_idx: usize,
    status: DataTransferPoolEntryState,
}

impl DataPoolEntry {
    /// Get access to the payload data
    pub fn get_data(&self) -> &[u8] {
        &self.data[self.start_idx..self.end_idx]
    }

    /// Get the number of remaining free bytes
    fn remaining_append_bytes(&self) -> usize {
        self.data.len() - self.end_idx
    }

    const fn new() -> Self {
        Self {
            data: [0; DATA_POOL_ENTRY_BYTES],
            start_idx: 0,
            end_idx: 0,
            status: DataTransferPoolEntryState::UNUSED,
        }
    }
}

///This is the storage pool available to the data transfer api
/// We don't use the GenArena because serializing the Handle would
/// already take 2 registers
pub struct DataTransferPool {
    pool: [DataPoolEntry; DATA_POOL_ENTRY_COUNT],
}

impl DataTransferPool {
    pub const fn new() -> Self {
        Self {
            pool: [DataPoolEntry::new(); DATA_POOL_ENTRY_COUNT],
        }
    }

    pub fn alloc_entry(
        &mut self,
        direction: DataPoolDirection,
    ) -> Result<DataTransferPoolHandle, CapaError> {
        let (idx, entry) = match self
            .pool
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| entry.status == DataTransferPoolEntryState::UNUSED)
        {
            Some(v) => v,
            None => {
                log::error!("DataTransferPool : did not find empty slot!, slot usage:");
                for (idx, x) in self.pool.iter().enumerate() {
                    log::error!("idx {:02}, status {}", idx, x.status);
                }
                return Err(CapaError::OutOfMemory);
            }
        };

        match direction {
            DataPoolDirection::ToDomain(content) => {
                entry.status = DataTransferPoolEntryState::SendingToDomain;
                if content.len() > entry.data.len() {
                    log::error!("DataTransferPool, Direction ToDomain, requested to store {} bytes but can only store {}", content.len(), entry.data.len());
                    return Err(CapaError::OutOfMemory);
                }
                entry.data.fill(0);
                for (idx, x) in content.iter().enumerate() {
                    entry.data[idx] = *x;
                }
                entry.start_idx = 0;
                entry.end_idx = content.len();
            }
            DataPoolDirection::FromDomain => {
                entry.status = DataTransferPoolEntryState::ReceivingFromDomain;
                entry.data.fill(0);
                entry.start_idx = 0;
                entry.end_idx = 0;
            }
        }

        let handle = DataTransferPoolHandle::from_idx(idx)
            .expect("by construction, free_idx should be a valid value");
        Ok(handle)
    }

    pub fn append_to_entry(
        &mut self,
        handle: DataTransferPoolHandle,
        data: &[u8],
        finish_entry: bool,
    ) -> Result<(), CapaError> {
        let idx = handle.to_idx();
        let entry = &mut self.pool[idx];
        assert_eq!(
            entry.status,
            DataTransferPoolEntryState::ReceivingFromDomain
        );

        //entry.data.len() is the max len of the static array, next_idx manages the
        //next free idx and thus represents the current size
        if data.len() > entry.remaining_append_bytes() {
            return Err(CapaError::OutOfMemory);
        }

        for v in data {
            entry.data[entry.end_idx] = *v;
            entry.end_idx += 1;
        }

        if finish_entry {
            entry.status = DataTransferPoolEntryState::FromDomainReady;
        }
        Ok(())
    }

    pub fn max_entry_size() -> usize {
        DATA_POOL_ENTRY_BYTES
    }

    ///transfer ownership and mark entry as invalid
    pub fn consume_data_from_domain(
        &mut self,
        handle: DataTransferPoolHandle,
    ) -> Result<DataPoolEntry, CapaError> {
        let idx = handle.to_idx();
        let entry = &mut self.pool[idx];
        if entry.status != DataTransferPoolEntryState::FromDomainReady {
            return Err(CapaError::AccessToUnfinishedDataTransferEntry);
        }
        let output_copy = entry.clone();
        entry.status = DataTransferPoolEntryState::UNUSED;
        Ok(output_copy)
    }

    pub const TO_DOMAIN_CHUNCK_SIZE: usize = 3 * mem::size_of::<usize>();
    /// fixed size data, chunk, used bytes, remaining bytes
    pub fn take_chunk_to_send_to_domain(
        &mut self,
        handle: DataTransferPoolHandle,
    ) -> Result<([u8; Self::TO_DOMAIN_CHUNCK_SIZE], usize, usize), CapaError> {
        let idx = handle.to_idx();
        let entry = &mut self.pool[idx];
        if entry.status != DataTransferPoolEntryState::SendingToDomain {
            //TODO: refactor error value
            log::error!(
                "take_chunck_to_send_to_domain : entry has invalid state {}, expected {}",
                entry.status,
                DataTransferPoolEntryState::SendingToDomain
            );
            return Err(CapaError::AccessToUnfinishedDataTransferEntry);
        }

        let mut out_data = [0_u8; Self::TO_DOMAIN_CHUNCK_SIZE];
        let used_bytes = min(entry.get_data().len(), Self::TO_DOMAIN_CHUNCK_SIZE);
        for (idx, x) in entry
            .get_data()
            .iter()
            .enumerate()
            .take(Self::TO_DOMAIN_CHUNCK_SIZE)
        {
            out_data[idx] = *x;
        }
        entry.start_idx += used_bytes;
        assert!(entry.start_idx <= entry.end_idx);
        let remaining_bytes = entry.get_data().len();

        if remaining_bytes == 0 {
            entry.status = DataTransferPoolEntryState::UNUSED;
        }

        Ok((out_data, used_bytes, remaining_bytes))
    }
}
