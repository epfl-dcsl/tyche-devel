use core::fmt::Display;
use core::{mem, slice};

use vtd::queue_invalidation_regs::{DescriptorSize, RawDescriptor};

use super::iommu_register_offsets::DmarRegister;

/// SIze of the raw  data in PvIommuResult in usize
const PV_IOMMU_RESULT_USIZE: usize = 5;
/// Like `PV_IOMMU_RESULT_USIZE` but in bytes
const PV_IOMMU_RESULT_BYTES: usize = PV_IOMMU_RESULT_USIZE * mem::size_of::<usize>();

/// Common result struct for all commands. Just pass this back to the driver in dom0
pub struct PvIommuResult {
    /// buffer with max size
    raw_data: [u8; PV_IOMMU_RESULT_BYTES],
    /// actually used bytes in raw_data/ next free idx
    next_idx: usize,
}

impl PvIommuResult {
    pub const fn empty() -> Self {
        Self {
            raw_data: [0_u8; PV_IOMMU_RESULT_BYTES],
            next_idx: 0,
        }
    }

    pub fn append_u32(&mut self, v: u32) -> Result<(), ()> {
        if self.next_idx + mem::size_of::<u32>() > self.raw_data.len() {
            return Err(());
        }

        for x in v.to_ne_bytes() {
            self.raw_data[self.next_idx] = x;
            self.next_idx += 1
        }
        return Ok(());
    }

    pub fn append_u64(&mut self, v: u64) -> Result<(), ()> {
        if self.next_idx + mem::size_of::<u64>() > self.raw_data.len() {
            return Err(());
        }

        for x in v.to_ne_bytes() {
            self.raw_data[self.next_idx] = x;
            self.next_idx += 1
        }
        return Ok(());
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.raw_data[..self.next_idx]
    }

    pub fn get_raw(&self) -> [usize; PV_IOMMU_RESULT_USIZE] {
        unsafe {
            slice::from_raw_parts(
                self.raw_data.as_ptr() as *const usize,
                PV_IOMMU_RESULT_USIZE,
            )
        }
        .try_into()
        .unwrap()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Write u32 value
    TychePviommuWritel = 0,
    /// Write u64 value
    TychePviommuWriteq = 1,
    /// Read u32 value
    TychePvIommuReadl = 2,
    /// Read  u64 value
    TychePvIommuReadq = 3,
    /// Initialize Queued Invalidation interface
    TychePvIommuQiInit = 4,
    /// Read Queued Invalidation descriptor
    TychePvIommuQiDescRead = 5,
    /// Write Queued Invalidation descriptor
    TychePvIommuQiDescWrite = 6,
}

impl Command {
    pub fn from_raw(raw: usize) -> Result<Command, ()> {
        match raw {
            0 => Ok(Command::TychePviommuWritel),
            1 => Ok(Command::TychePviommuWriteq),
            2 => Ok(Command::TychePvIommuReadl),
            3 => Ok(Command::TychePvIommuReadq),
            4 => Ok(Command::TychePvIommuQiInit),
            5 => Ok(Command::TychePvIommuQiDescRead),
            6 => Ok(Command::TychePvIommuQiDescWrite),
            _ => Err(()),
        }
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let v = match self {
            Command::TychePviommuWritel => "TychePviommuWritel",
            Command::TychePviommuWriteq => "TychePviommuWriteq",
            Command::TychePvIommuReadl => "TychePvIommuReadl",
            Command::TychePvIommuReadq => "TychePvIommuReadq",
            Command::TychePvIommuQiInit => "TychePvIommuQiInit",
            Command::TychePvIommuQiDescRead => "TychePvIommuQiDescRead",
            Command::TychePvIommuQiDescWrite => "TychePvIommuQiDescWrite",
        };
        write!(f, "{}", v)
    }
}

/// Argument struct for `Command::TychePvIommuQiInit`
pub struct QiInitReq {
    pub desc_size: DescriptorSize,
}

impl QiInitReq {
    pub fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
        let want_bytes = mem::size_of::<u32>();
        if buf.len() < want_bytes {
            return Err("unexpected size of serialized input");
        }
        let v = u32::from_ne_bytes(buf[0..mem::size_of::<u32>()].try_into().unwrap());
        let desc_size =
            DescriptorSize::from_bytes(v as usize).map_err(|_| "invalid descriptor size")?;
        Ok(Self { desc_size })
    }
}

/// Argument struct for `Command::TychePvIommuQiDescRead`
pub struct QiDescReadReq {
    pub offset: usize,
}

impl QiDescReadReq {
    pub fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
        let want_bytes = mem::size_of::<u32>();
        if buf.len() < want_bytes {
            return Err("unexpected size of serialized input");
        }
        let v = u32::from_ne_bytes(buf[0..mem::size_of::<u32>()].try_into().unwrap());
        Ok(Self { offset: v as usize })
    }
}

/// Argument struct for `Command::TychePvIommuQiDescWrite`
pub struct QiDescWriteReq {
    #[allow(dead_code)]
    pub desc_size: DescriptorSize,
    pub offset: i32,
    pub raw_desc: RawDescriptor,
}

impl QiDescWriteReq {
    pub fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
        //size check + parse for fixed length components
        let want_prefix_bytes = mem::size_of::<u8>() + mem::size_of::<i32>();
        if buf.len() < want_prefix_bytes {
            return Err("unexpected size of serialized input");
        }
        let mut buf_off = 0;
        let desc_size = DescriptorSize::from_bytes(u8::from_ne_bytes(
            buf[buf_off..mem::size_of::<u8>()].try_into().unwrap(),
        ) as usize)
        .map_err(|_| "invalid descriptor size")?;
        buf_off += mem::size_of::<u8>();

        let desc_offset = i32::from_ne_bytes(
            buf[buf_off..(buf_off + mem::size_of::<i32>())]
                .try_into()
                .unwrap(),
        );

        //size check + parse for dynamically sized descriptor
        if buf.len() < desc_size.in_bytes() as usize + want_prefix_bytes {
            return Err("unexpected size of serialized input");
        }

        let raw_qw = unsafe {
            slice::from_raw_parts(
                buf.as_ptr().offset(want_prefix_bytes as isize) as *const u64,
                desc_size.in_qw(),
            )
        };

        let raw_desc = match desc_size {
            DescriptorSize::Small => RawDescriptor::new_small(raw_qw[0], raw_qw[1]),
            DescriptorSize::Large => {
                RawDescriptor::new_large(raw_qw[0], raw_qw[1], raw_qw[2], raw_qw[3])
            }
        };

        Ok(QiDescWriteReq {
            raw_desc,
            desc_size,
            offset: desc_offset,
        })
    }
}

/// Parse specified values from raw buffer
pub fn deserialize_regoff_u32val(raw_buf: &[u8]) -> Result<(DmarRegister, u32), &'static str> {
    let raw_dmar_reg = u32::from_ne_bytes(
        raw_buf[0..mem::size_of::<u32>()]
            .try_into()
            .map_err(|_| "raw_buf to small for raw_dmar_reg")?,
    );
    let offset = mem::size_of::<u32>();
    let dmar_reg = (raw_dmar_reg as usize).try_into()?;

    let val = u32::from_ne_bytes(
        raw_buf[offset..(offset + mem::size_of::<u32>())]
            .try_into()
            .map_err(|_| "raw_buf too small for  u32 val")?,
    );

    return Ok((dmar_reg, val));
}

/// Parse specified values from raw buffer
pub fn deseriaize_regoff_u64val(raw_buf: &[u8]) -> Result<(DmarRegister, u64), &'static str> {
    let raw_dmar_reg = u32::from_ne_bytes(
        raw_buf[0..mem::size_of::<u32>()]
            .try_into()
            .map_err(|_| "raw_buf too small for dmar_reg")?,
    );
    let offset = mem::size_of::<u32>();
    let dmar_reg = (raw_dmar_reg as usize).try_into()?;

    let val = u64::from_ne_bytes(
        raw_buf[offset..(offset + mem::size_of::<u64>())]
            .try_into()
            .map_err(|_| "raw_buf too small for u64 val")?,
    );

    return Ok((dmar_reg, val));
}

/// Parse specified value
pub fn deserialize_reogoff(raw_buf: &[u8]) -> Result<DmarRegister, &'static str> {
    let raw_dmar_reg = u32::from_ne_bytes(
        raw_buf[0..mem::size_of::<u32>()]
            .try_into()
            .map_err(|_| "raw_buf to small for dmar_reg")?,
    );
    let dmar_reg = (raw_dmar_reg as usize).try_into()?;

    return Ok(dmar_reg);
}

pub fn serialize_readl_result(value: u32) -> PvIommuResult {
    let mut res = PvIommuResult::empty();
    res.append_u32(value).unwrap();
    res
}

pub fn serialize_readq_result(value: u64) -> PvIommuResult {
    let mut res = PvIommuResult::empty();
    res.append_u64(value).unwrap();
    res
}
