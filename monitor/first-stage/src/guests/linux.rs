//! Linux Guest

use bootloader::boot_info::MemoryRegionKind;
use mmu::RangeAllocator;
use stage_two_abi::GuestInfo;

use super::Guest;
use crate::acpi::AcpiInfo;
use crate::elf::{ElfMapping, ElfProgram};
use crate::guests::boot_params::{
    BootParams, E820Types, KERNEL_BOOT_FLAG_MAGIC, KERNEL_HDR_MAGIC, KERNEL_LOADER_OTHER,
    KERNEL_MIN_ALIGNMENT_BYTES,
};
use crate::guests::ManifestInfo;
use crate::mmu::MemoryMap;
use crate::vmx::{GuestPhysAddr, GuestVirtAddr};

#[cfg(feature = "guest_linux")]
const LINUXBYTES: &'static [u8] = include_bytes!("../../../../builds/linux-x86/vmlinux");
#[cfg(not(feature = "guest_linux"))]
const LINUXBYTES: &'static [u8] = &[0; 10];

#[allow(dead_code)]
const LINUX_MASK: u64 = 0xffffffff82000000;
// Offset of setup_header within the boot_params structure as specified in:
// linux/arch/x86/include/uapi/asm/bootparam.h
#[allow(dead_code)]
const SETUP_HDR: u64 = 0x1f1;

// WARNING: Don't forget that the command line must be null terminated ('\0')!
#[cfg(not(feature = "bare_metal"))]
static COMMAND_LINE: &'static [u8] =
    b"root=/dev/sdb2 apic=debug earlyprintk=serial,ttyS0 console=ttyS0 iommu=on iommu.passthrough=1 intremap=nopost iommu.strict=1 tyche.use_reserved_memory=1 tyche.reserved_base=0x200000000 tyche.reserved_size=4 memmap=4G$0x200000000\0";
#[cfg(feature = "bare_metal")]
static COMMAND_LINE: &'static [u8] =
    b"root=/dev/sdb2 apic=debug earlyprintk=serial,ttyS0,115200 console=ttyS0,115200\0";

pub struct Linux {}

pub const LINUX: Linux = Linux {};

impl Guest for Linux {
    unsafe fn instantiate(
        &self,
        acpi: &AcpiInfo,
        host_allocator: &impl RangeAllocator,
        guest_allocator: &impl RangeAllocator,
        memory_map: &MemoryMap,
        rsdp: u64,
    ) -> ManifestInfo {
        let mut manifest = ManifestInfo::default();
        let mut linux_prog = ElfProgram::new(LINUXBYTES);
        linux_prog.set_mapping(ElfMapping::Identity);
        let virtoffset = host_allocator.get_physical_offset();

        // Load guest into memory.
        let mut loaded_linux = linux_prog
            .load::<GuestPhysAddr, GuestVirtAddr>(guest_allocator, virtoffset)
            .expect("Failed to load guest");

        // Setup I/O MMU
        if let Some(_) = &acpi.iommu {
            manifest.iommu = 0;
        }

        // Build the boot params
        let mut boot_params = build_bootparams(&memory_map);
        let command_line = loaded_linux.add_payload(COMMAND_LINE, guest_allocator);
        let command_line_addr_low = (command_line.as_usize() & 0xFFFF_FFFF) as u32;
        let command_line_addr_high = (command_line.as_usize() >> 32) as u32;
        boot_params.ext_cmd_line_ptr = command_line_addr_high;
        boot_params.hdr.cmd_line_ptr = command_line_addr_low;
        boot_params.hdr.cmdline_size = COMMAND_LINE.len() as u32;
        boot_params.acpi_rsdp_addr = rsdp;
        let boot_params = loaded_linux.add_payload(boot_params.as_bytes(), guest_allocator);
        let entry_point = linux_prog.phys_entry;
        let mut info = GuestInfo::default();
        info.cr3 = loaded_linux.pt_root.as_usize();
        info.rip = entry_point.as_usize();
        info.rsp = 0;
        info.rsi = boot_params.as_usize();
        info.loaded = true;
        manifest.guest_info = info;

        manifest
    }
}

fn build_bootparams(memory_map: &MemoryMap) -> BootParams {
    let mut boot_params = BootParams::default();
    boot_params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    boot_params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    boot_params.hdr.header = KERNEL_HDR_MAGIC;
    boot_params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    // The initramfs is embedded so not sure we need to do any of that
    //boot_params.hdr.ramdisk_image = ramdisk addr;
    //boot_params.hdr.ramdisk_size = ramdisk size;
    for region in memory_map.guest {
        let addr = GuestPhysAddr::new(region.start as usize);
        let size = region.end - region.start;
        let kind = match region.kind {
            MemoryRegionKind::Usable => E820Types::Ram,
            MemoryRegionKind::Bootloader => E820Types::Ram,
            MemoryRegionKind::UnknownUefi(_) => E820Types::Reserved,
            MemoryRegionKind::UnknownBios(_) => E820Types::Reserved,
            _ => todo!("Add missing kind when updating bootloader crate"),
        };
        boot_params
            .add_e820_entry(addr, size, kind)
            .expect("Failed to add region");
    }

    boot_params
}
