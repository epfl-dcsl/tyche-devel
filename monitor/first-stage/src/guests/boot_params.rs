//! Boot parameters declaration.
//!
//! Mostly copied from linux/arch/x86/include/uapi/asm/bootparam.h

use core::mem;

pub use ffi::{BootParams, SetupHeader};

use crate::vmx::GuestPhysAddr;

mod ffi {
    #![allow(non_camel_case_types)]

    use core::ffi;

    pub type __s8 = ffi::c_schar;
    pub type __u8 = ffi::c_uchar;
    pub type __s16 = ffi::c_short;
    pub type __u16 = ffi::c_ushort;
    pub type __s32 = ffi::c_int;
    pub type __u32 = ffi::c_uint;
    pub type __s64 = ffi::c_longlong;
    pub type __u64 = ffi::c_ulonglong;

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct ScreenInfo {
        pub orig_x: __u8,             /* 0x00 */
        pub orig_y: __u8,             /* 0x01 */
        pub ext_mem_k: __u16,         /* 0x02 */
        pub orig_video_page: __u16,   /* 0x04 */
        pub orig_video_mode: __u8,    /* 0x06 */
        pub orig_video_cols: __u8,    /* 0x07 */
        pub flags: __u8,              /* 0x08 */
        pub unused2: __u8,            /* 0x09 */
        pub orig_video_ega_bx: __u16, /* 0x0a */
        pub unused3: __u16,           /* 0x0c */
        pub orig_video_lines: __u8,   /* 0x0e */
        pub orig_video_is_vga: __u8,  /* 0x0f */
        pub orig_video_points: __u16, /* 0x10 */

        /* VESA graphic mode -- linear frame buffer */
        pub lfb_width: __u16,       /* 0x12 */
        pub lfb_height: __u16,      /* 0x14 */
        pub lfb_depth: __u16,       /* 0x16 */
        pub lfb_base: __u32,        /* 0x18 */
        pub lfb_size: __u32,        /* 0x1c */
        pub cl_magic: __u16,        /* 0x20 */
        pub cl_offset: __u16,       /* 0x22 */
        pub lfb_linelength: __u16,  /* 0x24 */
        pub red_size: __u8,         /* 0x26 */
        pub red_pos: __u8,          /* 0x27 */
        pub green_size: __u8,       /* 0x28 */
        pub green_pos: __u8,        /* 0x29 */
        pub blue_size: __u8,        /* 0x2a */
        pub blue_pos: __u8,         /* 0x2b */
        pub rsvd_size: __u8,        /* 0x2c */
        pub rsvd_pos: __u8,         /* 0x2d */
        pub vesapm_seg: __u16,      /* 0x2e */
        pub vesapm_off: __u16,      /* 0x30 */
        pub pages: __u16,           /* 0x32 */
        pub vesa_attributes: __u16, /* 0x34 */
        pub capabilities: __u32,    /* 0x36 */
        pub ext_lfb_base: __u32,    /* 0x3a */
        pub _reserved: [__u8; 2],   /* 0x3e */
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct ApmBiosInfo {
        pub version: __u16,
        pub cseg: __u16,
        pub offset: __u32,
        pub cseg_16: __u16,
        pub dseg: __u16,
        pub flags: __u16,
        pub cseg_len: __u16,
        pub cseg_16_len: __u16,
        pub dseg_len: __u16,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct IstInfo {
        pub signature: __u32,
        pub command: __u32,
        pub event: __u32,
        pub perf_level: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct SysDescTable {
        pub length: __u16,
        pub table: [__u8; 14],
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct OlpcOfwHeader {
        pub ofw_magic: __u32, /* OFW signature */
        pub ofw_version: __u32,
        pub cif_handler: __u32, /* callback into OFW */
        pub irq_desc_table: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Copy, Clone)]
    pub struct EdidInfo {
        pub dummy: [__u8; 128],
    }

    impl Default for EdidInfo {
        fn default() -> Self {
            Self { dummy: [0; 128] }
        }
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct EfiInfo {
        pub efi_loader_signature: __u32,
        pub efi_systab: __u32,
        pub efi_memdesc_size: __u32,
        pub efi_memdesc_version: __u32,
        pub efi_memmap: __u32,
        pub efi_memmap_size: __u32,
        pub efi_systab_hi: __u32,
        pub efi_memmap_hi: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct SetupHeader {
        pub setup_sects: __u8,
        pub root_flags: __u16,
        pub syssize: __u32,
        pub ram_size: __u16,
        pub vid_mode: __u16,
        pub root_dev: __u16,
        pub boot_flag: __u16,
        pub jump: __u16,
        pub header: __u32,
        pub version: __u16,
        pub realmode_swtch: __u32,
        pub start_sys_seg: __u16,
        pub kernel_version: __u16,
        pub type_of_loader: __u8,
        pub loadflags: __u8,
        pub setup_move_size: __u16,
        pub code32_start: __u32,
        pub ramdisk_image: __u32,
        pub ramdisk_size: __u32,
        pub bootsect_kludge: __u32,
        pub heap_end_ptr: __u16,
        pub ext_loader_ver: __u8,
        pub ext_loader_type: __u8,
        pub cmd_line_ptr: __u32,
        pub initrd_addr_max: __u32,
        pub kernel_alignment: __u32,
        pub relocatable_kernel: __u8,
        pub min_alignment: __u8,
        pub xloadflags: __u16,
        pub cmdline_size: __u32,
        pub hardware_subarch: __u32,
        pub hardware_subarch_data: __u64,
        pub payload_offset: __u32,
        pub payload_length: __u32,
        pub setup_data: __u64,
        pub pref_address: __u64,
        pub init_size: __u32,
        pub handover_offset: __u32,
        pub kernel_info_offset: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct BootE820Entry {
        pub addr: __u64,
        pub size: __u64,
        pub typ: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct ISA {
        pub base_address: __u16,
        pub reserved1: __u16,
        pub reserved2: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct PCI {
        pub bus: __u8,
        pub slot: __u8,
        pub function: __u8,
        pub channel: __u8,
        pub reserved: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct S1 {
        pub reserved: __u64,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub union InterfacePath {
        pub isa: ISA,
        pub pci: PCI,
        pub ibnd: S1,
        pub xprs: S1,
        pub htpt: S1,
        pub unknown: S1,
    }

    impl Default for InterfacePath {
        fn default() -> Self {
            Self {
                unknown: S1::default(),
            }
        }
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct ATA {
        pub device: __u8,
        pub reserved1: __u8,
        pub reserved2: __u16,
        pub reserved3: __u32,
        pub reserved4: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct ATAPI {
        pub device: __u8,
        pub lun: __u8,
        pub reserved1: __u8,
        pub reserved2: __u8,
        pub reserved3: __u32,
        pub reserved4: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct SCSI {
        pub id: __u16,
        pub lun: __u64,
        pub reserved1: __u16,
        pub reserved2: __u32,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct USB {
        pub serial_number: __u64,
        pub reserved: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct I1394 {
        pub eui: __u64,
        pub reserved: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct FIBRE {
        pub wwid: __u64,
        pub lun: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct I2O {
        pub identity_tag: __u64,
        pub reserved: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct RAID {
        pub array_number: __u32,
        pub reserved1: __u32,
        pub reserved2: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct SATA {
        pub device: __u8,
        pub reserved1: __u8,
        pub reserved2: __u16,
        pub reserved3: __u32,
        pub reserved4: __u64,
    }

    #[repr(C, packed)]
    #[derive(Debug, Default, Copy, Clone)]
    pub struct UNKNOWN {
        pub reserved1: __u64,
        pub reserved2: __u64,
    }

    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub union DevicePath {
        pub ata: ATA,
        pub atapi: ATAPI,
        pub scsi: SCSI,
        pub usb: USB,
        pub i1394: I1394,
        pub fibre: FIBRE,
        pub i2o: I2O,
        pub raid: RAID,
        pub sata: SATA,
        pub unknown: UNKNOWN,
    }

    impl Default for DevicePath {
        fn default() -> Self {
            Self {
                unknown: Default::default(),
            }
        }
    }

    #[repr(C, packed)]
    #[derive(Default, Copy, Clone)]
    pub struct edd_device_params {
        pub length: __u16,
        pub info_flags: __u16,
        pub num_default_cylinders: __u32,
        pub num_default_heads: __u32,
        pub sectors_per_track: __u32,
        pub number_of_sectors: __u64,
        pub bytes_per_sector: __u16,
        pub dpte_ptr: __u32,               /* 0xFFFFFFFF for our purposes */
        pub key: __u16,                    /* = 0xBEDD */
        pub device_path_info_length: __u8, /* = 44 */
        pub reserved2: __u8,
        pub reserved3: __u16,
        pub host_bus_type: [__u8; 4],
        pub interface_type: [__u8; 8],
        pub interface_path: InterfacePath,
        pub device_path: DevicePath,
        pub reserved4: __u8,
        pub checksum: __u8,
    }

    #[repr(C, packed)]
    #[derive(Default, Copy, Clone)]
    pub struct EddInfo {
        pub device: __u8,
        pub version: __u8,
        pub interface_support: __u16,
        pub legacy_max_cylinder: __u16,
        pub legacy_max_head: __u8,
        pub legacy_sectors_per_track: __u8,
        pub params: edd_device_params,
    }

    /* max number of signatures to store */
    pub const EDD_MBR_SIG_MAX: usize = 16;

    /* number of edd_info structs starting at EDDBUF  */
    pub const EDDMAXNR: usize = 6;

    /*
     * This is the maximum number of entries in struct boot_params::e820_table
     * (the zeropage), which is part of the x86 boot protocol ABI:
     */
    pub const E820_MAX_ENTRIES_ZEROPAGE: usize = 128;

    /* The so-called "zeropage" */
    #[repr(C, packed)]
    #[derive(Copy, Clone)]
    pub struct BootParams {
        pub screen_info: ScreenInfo,    /* 0x000 */
        pub apm_bios_info: ApmBiosInfo, /* 0x040 */
        pub _pad2: [__u8; 4],           /* 0x054 */
        pub tboot_addr: __u64,          /* 0x058 */
        pub ist_info: IstInfo,          /* 0x060 */
        pub acpi_rsdp_addr: __u64,      /* 0x070 */
        pub _pad3: [__u8; 8],           /* 0x078 */
        pub hd0_info: [__u8; 16],       /* obsolete! */
        /* 0x080 */
        pub hd1_info: [__u8; 16], /* obsolete! */
        /* 0x090 */
        pub sys_desc_table: SysDescTable, /* obsolete! */
        /* 0x0a0 */
        pub olpc_ofw_header: OlpcOfwHeader, /* 0x0b0 */
        pub ext_ramdisk_image: __u32,       /* 0x0c0 */
        pub ext_ramdisk_size: __u32,        /* 0x0c4 */
        pub ext_cmd_line_ptr: __u32,        /* 0x0c8 */
        pub _pad4: [__u8; 116],             /* 0x0cc */
        pub edid_info: EdidInfo,            /* 0x140 */
        pub efi_info: EfiInfo,              /* 0x1c0 */
        pub alt_mem_k: __u32,               /* 0x1e0 */
        pub scratch: __u32,                 /* Scratch field! */
        /* 0x1e4 */
        pub e820_entries: __u8,            /* 0x1e8 */
        pub eddbuf_entries: __u8,          /* 0x1e9 */
        pub edd_mbr_sig_buf_entries: __u8, /* 0x1ea */
        pub kbd_status: __u8,              /* 0x1eb */
        pub secure_boot: __u8,             /* 0x1ec */
        pub _pad5: [__u8; 2],              /* 0x1ed */
        /*
         * The sentinel is set to a nonzero value (0xff) in header.S.
         *
         * A bootloader is supposed to only take setup_header and put
         * it into a clean boot_params buffer. If it turns out that
         * it is clumsy or too generous with the buffer, it most
         * probably will pick up the sentinel variable too. The fact
         * that this variable then is still 0xff will let kernel
         * know that some variables in boot_params are invalid and
         * kernel should zero out certain portions of boot_params.
         */
        pub _sentinel: __u8,  /* 0x1ef */
        pub _pad6: [__u8; 1], /* 0x1f0 */
        pub hdr: SetupHeader, /* setup header */
        /* 0x1f1 */
        pub _pad7: [__u8; 0x290 - 0x1f1 - 0x7b], //  0x7f is supposed to be setup header size
        pub edd_mbr_sig_buffer: [__u32; EDD_MBR_SIG_MAX], /* 0x290 */
        pub e820_table: [BootE820Entry; E820_MAX_ENTRIES_ZEROPAGE], /* 0x2d0 */
        pub _pad8: [__u8; 48],                   /* 0xcd0 */
        pub eddbuf: [EddInfo; EDDMAXNR],         /* 0xd00 */
        pub _pad9: [__u8; 276],                  /* 0xeec */
    }

    impl Default for BootParams {
        fn default() -> Self {
            Self {
                screen_info: Default::default(),
                apm_bios_info: Default::default(),
                _pad2: Default::default(),
                tboot_addr: Default::default(),
                ist_info: Default::default(),
                acpi_rsdp_addr: Default::default(),
                _pad3: Default::default(),
                hd0_info: Default::default(),
                hd1_info: Default::default(),
                sys_desc_table: Default::default(),
                olpc_ofw_header: Default::default(),
                ext_ramdisk_image: Default::default(),
                ext_ramdisk_size: Default::default(),
                ext_cmd_line_ptr: Default::default(),
                _pad4: [0; 116],
                edid_info: Default::default(),
                efi_info: Default::default(),
                alt_mem_k: Default::default(),
                scratch: Default::default(),
                e820_entries: Default::default(),
                eddbuf_entries: Default::default(),
                edd_mbr_sig_buf_entries: Default::default(),
                kbd_status: Default::default(),
                secure_boot: Default::default(),
                _pad5: Default::default(),
                _sentinel: Default::default(),
                _pad6: Default::default(),
                hdr: Default::default(),
                _pad7: [0; 0x290 - 0x1f1 - 0x7b],
                edd_mbr_sig_buffer: Default::default(),
                e820_table: [BootE820Entry::default(); E820_MAX_ENTRIES_ZEROPAGE],
                _pad8: [0; 48],
                eddbuf: [EddInfo::default(); EDDMAXNR],
                _pad9: [0; 276],
            }
        }
    }
}

#[derive(Debug)]
pub enum BootParamError {
    /// Invalid e820 setup params.
    E820Configuration,
}

#[derive(Debug)]
pub struct E820Entry {
    pub addr: GuestPhysAddr,
    pub size: u64,
    pub mem_type: E820Types,
}

impl BootParams {
    /// Adds an e820 region to the e820 map.
    /// Returns Ok(()) if successful, or an error if there is no space left in the map.
    pub fn add_e820_entry(&mut self, entry: E820Entry) -> Result<(), BootParamError> {
        if self.e820_entries >= self.e820_table.len() as u8 {
            return Err(BootParamError::E820Configuration);
        }

        let idx = self.e820_entries as usize;
        self.e820_table[idx].addr = entry.addr.as_u64();
        self.e820_table[idx].size = entry.size;
        self.e820_table[idx].typ = entry.mem_type as u32;
        self.e820_entries += 1;

        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

#[derive(Debug)]
#[repr(u32)]
pub enum E820Types {
    Ram = 1,
    Reserved = 2,
    ACPI = 3,
    NVS = 4,
    UNUSABLE = 5,
}

pub const KERNEL_LOADER_OTHER: u8 = 0xff;
pub const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
pub const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
pub const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000; // Must be non-zero.

// Where BIOS/VGA magic would live on a real PC.
pub const EBDA_START: u64 = 0x9fc00;
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
/// Size of MMIO gap at top of 32-bit address space.
pub const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
/// The start of the memory area reserved for MMIO devices.
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
/// The size of the memory area reserved for MMIO devices.
pub const MMIO_MEM_SIZE: u64 = MEM_32BIT_GAP_SIZE;

/// Types that can be read from raw bytes.
///
/// SAFETY: This trait must be implemented only on types that contains plain value. Implememting
/// this trait on a type that contains pointers or references (even nested in other structs) leads
/// to undefined behavior.
pub unsafe trait FromBytes: Sized + Clone {
    const SIZE: usize = mem::size_of::<Self>();

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }

        // Safety: The trait must be implememted only for struct that don't contain pointers or
        // reference, and a lenght check was performed just above.
        unsafe {
            let ptr = bytes.as_ptr() as *const Self;
            Some(ptr.read_unaligned())
        }
    }
}

unsafe impl FromBytes for BootParams {}
unsafe impl FromBytes for SetupHeader {}
