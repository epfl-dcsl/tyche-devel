/// Paravirtualization interface to the IOMMU that does GPA to HPA translation
/// for the features of the IOMMU that do not use DMA remapping
///
use core::fmt::Display;
use core::{mem, slice};

use capa_engine::{Domain, Handle};
use iommu_register_offsets::DmarRegister;
use mmu::walker::Address;
use spin::Mutex;
use vmx::{GuestPhysAddr, HostPhysAddr};
use vtd::queue_invalidation_regs::{
    DescType, DescriptorSize, InvalidationWaitDescriptor, RawDescriptor,
};
use vtd::Iommu;

use crate::allocator::allocator;
use crate::monitor::PlatformState;

mod iommu_register_offsets;
mod serialize_deserialize;

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
    const fn empty() -> Self {
        Self {
            raw_data: [0_u8; PV_IOMMU_RESULT_BYTES],
            next_idx: 0,
        }
    }

    fn append_u32(&mut self, v: u32) -> Result<(), ()> {
        if self.next_idx + mem::size_of::<u32>() > self.raw_data.len() {
            return Err(());
        }

        for x in v.to_ne_bytes() {
            self.raw_data[self.next_idx] = x;
            self.next_idx += 1
        }
        return Ok(());
    }

    fn append_u64(&mut self, v: u64) -> Result<(), ()> {
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

pub enum CommandWithArgs {
    PvIommuWritel { target_offset: u64, value: u32 },
}

/// Argument struct for `Command::TychePvIommuQiInit`
pub struct QiInitReq {
    desc_size: DescriptorSize,
}

impl QiInitReq {
    fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
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
    offset: usize,
}

impl QiDescReadReq {
    fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
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
    desc_size: DescriptorSize,
    offset: i32,
    raw_desc: RawDescriptor,
}

impl QiDescWriteReq {
    fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
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
fn deseriaize_regoff_u32val(raw_buf: &[u8]) -> Result<(DmarRegister, u32), &'static str> {
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
fn deseriaize_regoff_u64val(raw_buf: &[u8]) -> Result<(DmarRegister, u64), &'static str> {
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
fn deserialize_reogoff(raw_buf: &[u8]) -> Result<DmarRegister, &'static str> {
    let raw_dmar_reg = u32::from_ne_bytes(
        raw_buf[0..mem::size_of::<u32>()]
            .try_into()
            .map_err(|_| "raw_buf to small for dmar_reg")?,
    );
    let dmar_reg = (raw_dmar_reg as usize).try_into()?;

    return Ok(dmar_reg);
}

fn serialize_readl_result(value: u32) -> PvIommuResult {
    let mut res = PvIommuResult::empty();
    res.append_u32(value).unwrap();
    res
}

fn serialize_readq_result(value: u64) -> PvIommuResult {
    let mut res = PvIommuResult::empty();
    res.append_u64(value).unwrap();
    res
}

pub struct DomainAccessibleHPA {
    hpa: HostPhysAddr,
}

impl DomainAccessibleHPA {
    pub fn new(
        gpa: GuestPhysAddr,
        domain: &mut Handle<Domain>,
        domain_state: &impl PlatformState,
    ) -> Result<Self, &'static str> {
        let hpa = match domain_state.get_hpa(*domain, gpa) {
            Some(v) => v,
            None => return Err("gpa not mapped for domain"),
        };
        Ok(Self { hpa })
    }

    pub fn get_inner(&self) -> HostPhysAddr {
        self.hpa
    }
}

struct ReverseMap {
    reverse_map: [(HostPhysAddr, GuestPhysAddr); 256],
    rm_next_idx: usize,
}

impl ReverseMap {
    const fn new() -> Self {
        Self {
            reverse_map: [(HostPhysAddr::zero(), GuestPhysAddr::zero()); 256],
            rm_next_idx: 0,
        }
    }

    fn store(&mut self, hpa: HostPhysAddr, gpa: GuestPhysAddr) {
        //this is sized large enough that we should never overwrite any entry that we still need
        //TODO: better data structure, invalidate once descriptor has been processed
        self.reverse_map[self.rm_next_idx] = (hpa, gpa);
        self.rm_next_idx = (self.rm_next_idx + 1) % self.reverse_map.len();
    }

    fn get_gpa(&self, hpa: HostPhysAddr) -> Option<GuestPhysAddr> {
        for (s_hpa, s_gpa) in self.reverse_map {
            if s_hpa == hpa {
                return Some(s_gpa);
            }
        }
        return None;
    }
}

impl Default for ReverseMap {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ParavirtIOMMU {
    hw_iommu: &'static Mutex<Iommu>,
    ///Stores the GPA for the HPA that we put into IqaReg
    reverse_map: ReverseMap,
    /// Store the GPA for the HPA that we have written to DmarRegister::IrtaReg
    irta_gpa: Option<GuestPhysAddr>,
}

impl ParavirtIOMMU {
    pub const fn new(hw_iommu: &'static Mutex<Iommu>) -> Self {
        ParavirtIOMMU {
            hw_iommu,
            reverse_map: ReverseMap::new(),
            irta_gpa: None,
        }
    }

    /// low level write to register
    fn write<T>(base_mapping: *mut u8, offset: DmarRegister, value: T) {
        unsafe { (base_mapping.offset(offset as isize) as *mut T).write_volatile(value) }
    }

    /// low level read from register
    fn read<T>(base_mapping: *const u8, offset: DmarRegister) -> T {
        unsafe { (base_mapping.offset(offset as isize) as *const T).read_volatile() }
    }

    /// Apply paravirtualization logic and write to register
    fn pv_write_x<T>(
        &mut self,
        mapping: *mut u8,
        target: DmarRegister,
        value: T,
        calling_domain: &mut Handle<Domain>,
        domain_state: &impl PlatformState,
    ) -> Result<(), &'static str>
    where
        T: Into<u64>,
        T: Copy,
    {
        match target {
            DmarRegister::RtaddrReg => {
                return Err("tried to write to root table address register!");
            }
            DmarRegister::GcmdReg => {
                let dma_remap_enable_mask: u64 = 1 << 31;
                let mut sanitized_value: u64 = value.into();
                if sanitized_value & dma_remap_enable_mask == 0 {
                    sanitized_value |= dma_remap_enable_mask;
                    log::warn!("tried to disable dma remapping suppressing change : input 0b{:064b}, sanitized 0b{:064b}", value.into(), sanitized_value);
                }

                let srtp_mask: u64 = 1 << 30;
                if sanitized_value & srtp_mask != 0 {
                    sanitized_value &= !srtp_mask;
                    log::warn!(
                        "tried to notify about new root table pointer via srtp, suppressing change : input 0b{:064b}, sanitized 0b{:064b}", value.into(), sanitized_value);
                }
                Self::write(mapping, target, sanitized_value);
            }
            DmarRegister::IqaReg => {
                return Err("tried to write to inv queue address reg");
            }
            // This should only be advanced by HW, SW should not write
            DmarRegister::IqhReg => {
                return Err("tried to write to inv queue head reg");
            }
            // Stores pointer to guest allocated interrupt remapping table -> replace with HPA
            DmarRegister::IrtaReg => {
                //addr is 4KiB aligned, offfset bits are used for config flags
                let config_bits: u64 = value.into() & 0xfff;
                let gpa = GuestPhysAddr::from_u64(value.into() & !0xfff);
                let hpa = DomainAccessibleHPA::new(gpa, calling_domain, domain_state)?;

                self.irta_gpa = Some(gpa);
                let new_value = hpa.get_inner().as_u64() | config_bits;
                log::info!(
                    "write to {}, replacing GPA 0x{:013x} with HPA 0x{:013x}, HPA with config bits in offset 0x{:013x}",
                    target,
                    gpa.as_u64(),
                    hpa.get_inner().as_u64(),
                    new_value,
                );
                Self::write(mapping, target, new_value)
            }
            _ => Self::write(mapping, target, value),
        };
        Ok(())
    }

    /// Check paravirtualization logic and read from register
    fn pv_read_x<T>(&self, mapping: *mut u8, target: DmarRegister) -> Result<T, &'static str>
    where
        T: TryFrom<u64>,
        T: Into<u64>,
    {
        let raw_value: T = Self::read(mapping, target);
        let result_value = match target {
            DmarRegister::IqaReg => {
                return Err("IqaReg used in Readl");
            }
            // Stores pointer to guest allocated interrupt remapping table -> replace store HPA with GPA
            DmarRegister::IrtaReg => {
                let gpa = self.irta_gpa.ok_or("read to IrtaReg but no gpa stored")?;
                let off: u64 = raw_value.into() & 0xfff_u64;
                (off | (gpa.as_u64() & !0xfff))
                    .try_into()
                    .map_err(|_| "failed to coerce from u64 to type T")?
            }
            _ => raw_value,
        };
        Ok(result_value)
    }

    /// Execute command requested by dom0 driver
    /// # Arguments
    /// - `cmd` : Command from paravirt Linux driver
    /// - `raw_buf` : serialized arguments from paravirt Linux driver
    /// - `calling_domain` : handle for domain that tries to execute this command
    /// - `domain_state` : platform state for domain executing the command, we require this to do GPA<->HPA translation
    pub fn execute(
        &mut self,
        cmd: Command,
        raw_buf: &[u8],
        calling_domain: &mut Handle<Domain>,
        domain_state: &impl PlatformState,
    ) -> Result<PvIommuResult, &'static str> {
        let mut iommu = self.hw_iommu.lock();
        let mapping = iommu.as_ptr_mut();
        match cmd {
            Command::TychePviommuWritel => {
                let (target, value) = deseriaize_regoff_u32val(raw_buf)?;
                //log::info!("writel to {} with value 0x{:013x}", target, value);
                self.pv_write_x(mapping, target, value, calling_domain, domain_state)?;
                return Ok(PvIommuResult::empty());
            }
            Command::TychePviommuWriteq => {
                let (target, value) = deseriaize_regoff_u64val(raw_buf)?;
                //log::info!("writeq to {} with value 0x{:013x}", target, value);
                self.pv_write_x(mapping, target, value, calling_domain, domain_state)?;
                return Ok(PvIommuResult::empty());
            }
            Command::TychePvIommuReadl => {
                //TODO: fine grained analysis if reading can leak security sensitive data
                let target = deserialize_reogoff(raw_buf)?;
                let result_value = self.pv_read_x(mapping, target)?;

                let res_buf = serialize_readl_result(result_value);
                return Ok(res_buf);
            }
            Command::TychePvIommuReadq => {
                //TODO: fine grained analysis if reading can leak security sensitive data
                let target = deserialize_reogoff(raw_buf)?;
                let result_value = self.pv_read_x(mapping, target)?;

                let res_buf = serialize_readq_result(result_value);
                return Ok(res_buf);
            }
            Command::TychePvIommuQiInit => {
                let input = QiInitReq::deserialize(raw_buf)?;
                //log::info!("TychePVIommuQiInit");
                iommu.enable_quid_invalidation(input.desc_size, allocator())?;
                Ok(PvIommuResult::empty())
            }
            Command::TychePvIommuQiDescRead => {
                let input = QiDescReadReq::deserialize(raw_buf)?;
                let mut raw_desc = iommu.read_descriptor(input.offset)?;

                let desc_type = DescType::from_raw(raw_desc.as_qw()[0])
                    .map_err(|_| "invalid descriptor type")?;
                //log::info!("TychePvIommuQiDescRead: offset 0x{:x}", input.offset);
                match desc_type {
                    DescType::ContextCacheInvalidate => (),
                    //Replace stored HPA with GPA
                    DescType::InvalidationWaitDescriptor => {
                        let mut wait_desc = InvalidationWaitDescriptor::from_raw(&raw_desc)
                            .map_err(|_| "invalid wait descriptor while reading from queue")?;
                        let gpa = self
                            .reverse_map
                            .get_gpa(HostPhysAddr::from_u64(wait_desc.get_status_addr()))
                            .ok_or("did not find gpa in reverse map")?;
                        log::info!(
                            "Fixing WaitDescriptor HPA 0x{:013x} to GAP 0x{:013x}",
                            wait_desc.get_status_addr(),
                            gpa.as_u64(),
                        );
                        wait_desc.set_status_addr(gpa.as_u64());
                        raw_desc = wait_desc.bits(iommu.get_desc_size()?);
                    }
                    _ => (),
                }

                let mut out = PvIommuResult::empty();
                for qw in raw_desc.as_qw() {
                    out.append_u64(*qw).map_err(|_| "result buf overflow")?;
                }
                Ok(out)
            }
            Command::TychePvIommuQiDescWrite => {
                let input = QiDescWriteReq::deserialize(raw_buf)?;

                let desc_type = DescType::from_raw(input.raw_desc.as_qw()[0])
                    .map_err(|_| "invalid descriptor type")?;
                //log::info!("TychePvIommuQiDescWrite for desc type {}", desc_type);
                let mut sanitized_desc = input.raw_desc;
                match desc_type {
                    DescType::PasidBasedDeviceTlbInvalidate
                    | DescType::DeviceTlbInvalidate
                    | DescType::IotlbInvalidate => {
                        todo!("can contain addr, figure out rewriting {}", desc_type);
                    }
                    //Wait descriptor contains writeback GPA -> replace with HPA
                    DescType::InvalidationWaitDescriptor => {
                        let mut wait_desc = InvalidationWaitDescriptor::from_raw(&input.raw_desc)
                            .map_err(|_| "failed to parse wait descriptor")?;
                        let gpa = GuestPhysAddr::from_u64(wait_desc.get_status_addr());
                        let hpa = DomainAccessibleHPA::new(gpa, calling_domain, domain_state)?;
                        wait_desc.set_status_addr(hpa.get_inner().as_u64());
                        log::info!(
                            "WaitDescriptor, replaced GPA 0x{:013x} with HPA 0x{:013x}, new qw1 value 0x{:013x}",
                            gpa.as_u64(),
                            hpa.get_inner().as_u64(),
                            wait_desc.bits(iommu.get_desc_size().unwrap()).as_qw()[1],
                        );

                        self.reverse_map.store(hpa.get_inner(), gpa);

                        sanitized_desc = wait_desc.bits(iommu.get_desc_size()?);
                    }
                    _ => (),
                }

                iommu.write_descriptor(input.offset as usize, sanitized_desc)?;
                Ok(PvIommuResult::empty())
            }
        }
    }
}
