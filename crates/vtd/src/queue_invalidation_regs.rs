use core::fmt::Display;
use core::slice;

use vmx::Frame;

/// Register Definitions for the Queued Invalidation Interface
/// Specified in 6.5.2 of the VTD spec

// Define a const fn to create a bit mask for a given range. Both are inclusive
const fn bitmask(start: u32, end: u32) -> u64 {
    assert!(
        start <= end,
        "bitmask start start indice larger than end indice",
    );
    ((1u64 << (end - start + 1)) - 1) << start
}

///Invalidation Queue Head Register
/// 11.4.9 Invalidation Queue Interface
#[derive(Debug, Default, Clone, Copy)]
pub struct InvalidationQueueHead {
    queue_head: u64,
}

impl InvalidationQueueHead {
    /// Queue Head shift
    const QH_SHIFT: u64 = 4;
    /// Queue Head Mask
    const QH_MASK: u64 = bitmask(4, 18);

    pub fn new_from_bits(bits: u64) -> Self {
        let queue_head = (bits & Self::QH_MASK) >> Self::QH_SHIFT;

        Self { queue_head }
    }

    pub fn get_queue_head(&self) -> u64 {
        self.queue_head
    }
}

//11.4.9.2 Invalidation Queue Tail Register in VTD spec
#[derive(Debug, Default, Clone, Copy)]
pub struct InvalidationQueueTail {
    state: u64,
}

impl InvalidationQueueTail {
    const QT_SHIFT: u64 = 4;
    const QT_MASK: u64 = bitmask(Self::QT_SHIFT as u32, 18);

    pub fn set_queue_tail(&mut self, v: u64) -> Result<(), &'static str> {
        let shifted = v << Self::QT_SHIFT;
        if (shifted & !Self::QT_MASK) != 0 {
            return Err("value tail register is to large");
        }
        //reset current value
        self.state &= !Self::QT_MASK;
        //set new value
        self.state |= shifted;
        Ok(())
    }

    pub fn get_queue_tail(&self) -> u64 {
        (self.state & Self::QT_MASK) >> Self::QT_SHIFT
    }

    pub fn bits(&self) -> u64 {
        self.state
    }

    pub fn new_from_bits(bits: u64) -> Self {
        Self { state: bits }
    }

    pub fn new(tail_value: u64) -> Result<Self, &'static str> {
        let mut v = Self::default();
        v.set_queue_tail(tail_value)?;
        Ok(v)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RawDescriptor {
    raw_data: [u64; 4],
    width: DescriptorSize,
}

impl RawDescriptor {
    /// New, invalid small descriptor
    pub fn new_small(low: u64, high: u64) -> Self {
        Self {
            raw_data: [low, high, 0, 0],
            width: DescriptorSize::Small,
        }
    }

    /// New, invalid large descriptor
    pub fn new_large(qw1: u64, qw2: u64, qw3: u64, qw4: u64) -> Self {
        Self {
            raw_data: [qw1, qw2, qw3, qw4],
            width: DescriptorSize::Large,
        }
    }

    /// Return raw data as &[u64]
    pub fn as_qw(&self) -> &[u64] {
        &self.raw_data[0..self.width.in_qw()]
    }

    /// Return raw data as &[u8]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.raw_data.as_ptr() as *const u8, self.width.in_bytes()) }
    }
}

/// Invalidation Queue Tail Register Section 11.4.9.2
#[derive(Debug, Default, Clone, Copy)]
pub struct InvalidationQueueAddressRegister {
    ///Invalidation Queue Base Address
    iqa: u64,
    ///Descriptor Width
    dw: u64,
    ///Queue Size
    qs: u64,
}

impl InvalidationQueueAddressRegister {
    const IQA_MASK: u64 = bitmask(12, 63);

    const DW_SHIFT: u64 = 11;
    const DW_MASK: u64 = (1 << Self::DW_SHIFT);

    const QS_SHIFT: u64 = 0;
    const QS_MASK: u64 = bitmask(Self::QS_SHIFT as u32, 2);

    pub fn bits(&self) -> u64 {
        (self.iqa & Self::IQA_MASK) | (self.dw << Self::DW_SHIFT) | (self.qs << Self::QS_SHIFT)
    }

    /// 4 KiB aligned addr of invalidation request queue
    pub fn set_iqa(&mut self, addr: u64) {
        assert_eq!(addr & !Self::IQA_MASK, 0, "set iqa: addr not 4 KiB aligned");
        self.iqa = addr;
    }

    pub fn get_iqa(&self) -> u64 {
        self.iqa
    }

    /// Configure width of descriptors to either be 128 or 256 bits
    pub fn set_dw(&mut self, is_256_bit: bool) {
        self.dw = match is_256_bit {
            true => 1,
            false => 0,
        }
    }

    pub fn get_dw(&self) -> u64 {
        self.dw
    }

    /// Specify size of invalidation request queue. Order x means 2^x 4 KiB Pages
    pub fn set_qs(&mut self, order: u64) {
        self.qs = order;
    }

    pub fn get_qs(&self) -> u64 {
        self.qs
    }

    pub fn new_from_bits(bits: u64) -> Self {
        let iqa = bits & Self::IQA_MASK;
        let dw = (bits & Self::DW_MASK) >> Self::DW_SHIFT;
        let qs = (bits & Self::QS_MASK) >> Self::QS_SHIFT;

        Self { iqa, dw, qs }
    }
}

///Descritpor for invalidating the IOTLB
///  6.5.2.3 IOTLB Invalidate
// This structure is quite complex. For now we only implement
// "Flush all"
#[derive(Debug, Default, Clone, Copy)]
pub struct IOTLBInvalidateDescriptor {
    high: u64,
    low: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlushGranularity {
    GlobalInvalidation,
    DomainSelectiveInvalidation,
    PageSelectiveWithinDomainInvalidation,
}

impl FlushGranularity {
    pub fn bits(&self) -> u64 {
        match self {
            FlushGranularity::GlobalInvalidation => 0b01,
            FlushGranularity::DomainSelectiveInvalidation => 0b10,
            FlushGranularity::PageSelectiveWithinDomainInvalidation => 0b11,
        }
    }
}

impl IOTLBInvalidateDescriptor {
    const GRANULARITY_SHIFT: u64 = 4;
    /// Drain Reads pending before flushing
    const DR_FLAG: u64 = 1 << 7;
    /// Drain Writes pending writes before flushing
    const DW_FLAG: u64 = 1 << 6;

    /// Descriptor that flushes all TLB entries, waiting for pending reads and writes to be executed
    /// before flushing
    pub fn new_flush_all() -> Self {
        let desc_type: u64 = 0x2;
        let granularity: u64 =
            FlushGranularity::GlobalInvalidation.bits() << Self::GRANULARITY_SHIFT;

        let high: u64 = 0;
        let low: u64 = desc_type | granularity | Self::DR_FLAG | Self::DW_FLAG;

        Self { high, low }
    }

    /// Returns (high bits, low bits)
    pub fn bits(&self) -> RawDescriptor {
        RawDescriptor::new_small(self.low, self.high)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DescriptorSize {
    //128 bit
    Small,
    //256 bit
    Large,
}

impl DescriptorSize {
    pub fn in_bytes(&self) -> usize {
        match self {
            DescriptorSize::Small => 16,
            DescriptorSize::Large => 32,
        }
    }
    pub fn in_qw(&self) -> usize {
        self.in_bytes() / 8
    }

    pub fn from_bytes(bytes: usize) -> Result<DescriptorSize, ()> {
        match bytes {
            16 => Ok(DescriptorSize::Small),
            32 => Ok(DescriptorSize::Large),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DescType {
    ContextCacheInvalidate,
    IotlbInvalidate,
    DeviceTlbInvalidate,
    InterruptEntryCacheInvalidate,
    InvalidationWaitDescriptor,
    PasidBasedIotlbInvalidate,
    PasidCacheInvalidate,
    PasidBasedDeviceTlbInvalidate,
}

impl DescType {
    const MASK_HIGH: u64 = bitmask(9, 11);
    const MASK_LOW: u64 = bitmask(0, 3);

    /// Parses the type of a Invalidation descriptor from its first quad word
    pub fn from_raw(qw1: u64) -> Result<DescType, ()> {
        let high = qw1 & Self::MASK_HIGH;
        let low = qw1 & Self::MASK_LOW;
        //assemble 7 bit descriptor type value out of the two chuncks
        let v: u64 = (high >> 3) | low;

        match v {
            0x1 => Ok(Self::ContextCacheInvalidate),
            0x2 => Ok(Self::IotlbInvalidate),
            0x3 => Ok(Self::DeviceTlbInvalidate),
            0x4 => Ok(Self::InterruptEntryCacheInvalidate),
            0x5 => Ok(Self::InvalidationWaitDescriptor),
            0x6 => Ok(Self::PasidBasedIotlbInvalidate),
            0x7 => Ok(Self::PasidCacheInvalidate),
            0x8 => Ok(Self::PasidBasedDeviceTlbInvalidate),
            _ => Err(()),
        }
    }

    /// Or-mask to apply to first quadword of a descriptor to set this type
    pub fn as_low_qw_mask(&self) -> u64 {
        match self {
            DescType::ContextCacheInvalidate => 0x1,
            DescType::IotlbInvalidate => 0x2,
            DescType::DeviceTlbInvalidate => 0x3,
            DescType::InterruptEntryCacheInvalidate => 0x4,
            DescType::InvalidationWaitDescriptor => 0x5,
            DescType::PasidBasedIotlbInvalidate => 0x6,
            DescType::PasidCacheInvalidate => 0x7,
            DescType::PasidBasedDeviceTlbInvalidate => 0x8,
        }
    }
}

impl Display for DescType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let v = match self {
            DescType::ContextCacheInvalidate => "ContextCacheInvalidate",
            DescType::IotlbInvalidate => "IotlbInvalidate",
            DescType::DeviceTlbInvalidate => "DeviceTlbInvalidate",
            DescType::InterruptEntryCacheInvalidate => "InterruptEntryCacheInvalidate",
            DescType::InvalidationWaitDescriptor => "InvalidationWaitDescriptor",
            DescType::PasidBasedIotlbInvalidate => "PasidBasedIotlbInvalidate",
            DescType::PasidCacheInvalidate => "PasidCacheInvalidate",
            DescType::PasidBasedDeviceTlbInvalidate => "PasidBasedDeviceTlbInvalidate",
        };
        write!(f, "{}", v)
    }
}

///6.5.2.8 Invalidation Wait Descriptor

#[derive(Debug, Default, Clone, Copy)]
pub struct InvalidationWaitDescriptor {
    high: u64,
    low: u64,
}

impl InvalidationWaitDescriptor {
    /// Fixed value for type field that marks this as in invalidation
    /// wait descriptor
    const DESC_TYPE: DescType = DescType::InvalidationWaitDescriptor;

    const DW_FLAG: u64 = 0x1 << 5;

    const STATUS_DATA_SHIFT: u64 = 32;
    #[allow(dead_code)]
    const STATUS_DATA_MASK: u64 = bitmask(Self::STATUS_DATA_SHIFT as u32, 63);

    /// New wait descritptor. Poll `status_wb_addr` for `wb_value` to check check completion
    /// # Arguments
    /// - `status_wb_addr` : address to write value to once preceeding requests have completed
    /// - `wb_value` : value to write to `status_wb_addr` once preceeding requests have completed
    pub fn new(status_wb_addr: Frame, wb_value: u32) -> Self {
        let high = status_wb_addr.phys_addr.as_u64();
        assert_eq!(high % 4, 0, "Write back address needs to be 4 byte aligned");
        let low = Self::DESC_TYPE.as_low_qw_mask()
            | Self::DW_FLAG
            | ((wb_value as u64) << Self::STATUS_DATA_SHIFT);

        Self { high, low }
    }

    pub fn get_status_addr(&self) -> u64 {
        self.high & !0xfff
    }

    pub fn set_status_addr(&mut self, value: u64) {
        //save current status bits
        let status_buf = self.high & 0xfff;
        self.high = (value & !0xfff) | status_buf;
    }

    /// Returns (high bits, low bits)
    pub fn bits(&self, desc_type: DescriptorSize) -> RawDescriptor {
        match desc_type {
            DescriptorSize::Small => RawDescriptor::new_small(self.low, self.high),
            //256 bit just has 0 padding in upper bits
            DescriptorSize::Large => RawDescriptor::new_large(self.low, self.high, 0, 0),
        }
    }

    pub fn from_raw(raw: &RawDescriptor) -> Result<Self, ()> {
        let low = raw.as_qw()[0];
        let high = raw.as_qw()[1];

        let desc_type = DescType::from_raw(low)?;
        if desc_type != Self::DESC_TYPE {
            return Err(());
        }

        Ok(Self { high, low })
    }
}

pub struct ContextCacheInvalidateDescriptor {
    granularity: FlushGranularity,
}

impl ContextCacheInvalidateDescriptor {
    const DESC_TYPE: u64 = 0x1;

    const GRANULARITY_SHIFT: u64 = 4;
    #[allow(dead_code)]
    const GRANULARITY_MASK: u64 = bitmask(Self::GRANULARITY_SHIFT as u32, 5);

    pub fn new(granularity: FlushGranularity) -> Self {
        Self { granularity }
    }

    pub fn bits(&self) -> RawDescriptor {
        let high = 0;
        let low = Self::DESC_TYPE | (self.granularity.bits() << Self::GRANULARITY_SHIFT);
        RawDescriptor::new_small(low, high)
    }
}

#[cfg(test)]
mod test {
    use super::bitmask;

    #[test]
    pub fn bitmask_test() {
        let want_a = 0b0110;
        let got_a = bitmask(1, 2);
        assert_eq!(
            want_a, got_a,
            "Expected bitmask 0x{:x}, got 0x{:x}",
            want_a, got_a
        );

        let want_b = 0xff00_0000_0000_0000;
        let got_b = bitmask(56, 63);
        assert_eq!(
            want_b, got_b,
            "Expected bitmask 0x{:x}, got 0x{:x}",
            want_b, got_b
        );
    }
}
