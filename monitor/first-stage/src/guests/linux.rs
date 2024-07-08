//! Linux Guest

use core::ptr::slice_from_raw_parts;
use core::slice;

use mmu::ioptmapper::PAGE_SIZE;
use mmu::memory_coloring::MemoryColoring;
use mmu::RangeAllocator;
use qemu::println;
use stage_two_abi::GuestInfo;

use super::Guest;
use crate::acpi::AcpiInfo;
use crate::elf::relocate::relocate_elf;
use crate::elf::{Elf64PhdrType, ElfMapping, ElfProgram};
use crate::guests::boot_params::{
    BootParams, KERNEL_BOOT_FLAG_MAGIC, KERNEL_HDR_MAGIC, KERNEL_LOADER_OTHER,
    KERNEL_MIN_ALIGNMENT_BYTES,
};
use crate::guests::ManifestInfo;
use crate::mmu::frames::PartitionedMemoryMap;
use crate::print;
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
    b"root=/dev/sdb2 apic=debug earlyprintk=serial,ttyS0 console=ttyS0 iommu=off\0";
#[cfg(feature = "bare_metal")]
static COMMAND_LINE: &'static [u8] =
    b"root=/dev/sdb2 apic=debug earlyprintk=serial,ttyS0,115200 console=ttyS0,115200\0";

pub struct Linux {}

pub const LINUX: Linux = Linux {};

impl Guest for Linux {
    unsafe fn instantiate<T: MemoryColoring + Clone>(
        &self,
        acpi: &AcpiInfo,
        host_allocator: &impl RangeAllocator,
        guest_allocator: &impl RangeAllocator,
        memory_map: &PartitionedMemoryMap<T>,
        rsdp: u64,
    ) -> ManifestInfo {
        let mut manifest = ManifestInfo::default();
        let mut linux_prog = ElfProgram::new(LINUXBYTES);
        //luca: TODO: why do we load identity mapped? Why does this not break the codes addressing?
        linux_prog.set_mapping(ElfMapping::ScatteredPaddr);

        //this will associate SPAs with the correct color for all of the segments that we load later on
        relocate_elf(&mut linux_prog, guest_allocator, true);
        //If we are here, we have ensured that in the color space, linux will be a contiguous addresses and that
        //its first segment useses the `unused_prefix_bytes/PAGE_SIZE`-th entry in the color domain. As a result
        //this is important to ensure that we map the correct SPAs later on in the EPT construction
        //We want to have an identity map between GPAs on the compactified, color partitioned SPA space

        //debug print to get the first SPAs where linux is loaded
        for (load_segment_idx, load_segment) in linux_prog
            .segments
            .iter()
            .filter(|v| v.phdr.p_type == Elf64PhdrType::PT_LOAD.bits())
            .enumerate()
        {
            log::info!(
                "Linux load segment {:02}, load GPA 0x{:x}",
                load_segment_idx,
                load_segment.phdr.p_paddr
            );
            let mut linux_page_counter = 0;
            let abort_linux_page_print_at = 3;
            for phys_range in load_segment.phys_mem.iter().take(3) {
                let mut spa = phys_range.start.as_usize();
                while spa < phys_range.end.as_usize() {
                    log::info!("\t{:02}-th spa is 0x{:0x}", linux_page_counter, spa);
                    linux_page_counter += 1;
                    if linux_page_counter >= abort_linux_page_print_at {
                        break;
                    }
                    spa += PAGE_SIZE;
                }
                if linux_page_counter >= abort_linux_page_print_at {
                    break;
                }
            }
        }

        let virtoffset = host_allocator.get_physical_offset();

        //luca: this will do some allocations for the page tables
        // Load guest into memory.
        let mut loaded_linux = linux_prog
            .load(guest_allocator, virtoffset.as_usize(), true)
            .expect("Failed to load guest");

        log::info!("Dumping PT walk to linux entry in stage1 constructed PTS");
        match &mut loaded_linux.pt_mapper {
            crate::elf::ELfTargetEnvironment::Host(_) => todo!(),
            crate::elf::ELfTargetEnvironment::Guest(guest_mapper) => {
                guest_mapper.debug_range(
                    GuestVirtAddr::new(0x1000000),
                    0x1000,
                    mmu::walker::Level::L1,
                );
            }
        }

        // Setup I/O MMU
        if let Some(_) = &acpi.iommu {
            manifest.iommu = 0;
        }
        {
            let linux_exec_segment = linux_prog
                .segments
                .iter()
                .filter(|v| v.phdr.p_type == Elf64PhdrType::PT_LOAD.bits())
                .next()
                .expect("failed to get linux exec segment");
            let vaddr = linux_exec_segment.phys_mem[0].start.as_u64() + virtoffset.as_u64();
            let bytes_linux_exec = unsafe { slice::from_raw_parts(vaddr as *const u8, PAGE_SIZE) };
            log::info!("First few bytes of linux exec entry: ");
            for v in &bytes_linux_exec[..64] {
                print!("{:02x}", v);
            }
            println!("\n");
        }

        // Build the boot params
        // Step1: load values contained in BootParams into memory
        let mut boot_params = build_bootparams(&memory_map);
        let command_line = loaded_linux.add_payload(COMMAND_LINE, guest_allocator);
        log::info!(
            "color space gpa thingy for command line: 0x{:x}",
            command_line.as_u64()
        );
        let command_line_addr_low = (command_line.as_usize() & 0xFFFF_FFFF) as u32;
        let command_line_addr_high = (command_line.as_usize() >> 32) as u32;
        boot_params.ext_cmd_line_ptr = command_line_addr_high;
        boot_params.hdr.cmd_line_ptr = command_line_addr_low;
        boot_params.hdr.cmdline_size = COMMAND_LINE.len() as u32;
        boot_params.acpi_rsdp_addr = rsdp;
        //Step2 load the BootParams "struct" itself into memory
        let boot_params = loaded_linux.add_payload(boot_params.as_bytes(), guest_allocator);
        log::info!(
            "color space gpa thingy for boot params 0x{:x}",
            boot_params.as_u64()
        );
        let entry_point = linux_prog.phys_entry;
        let mut info = GuestInfo::default();
        info.cr3 = match loaded_linux.pt_mapper {
            crate::elf::ELfTargetEnvironment::Host(_) => {
                panic!("loaded linux guset using host mapper")
            }
            crate::elf::ELfTargetEnvironment::Guest(guest) => guest.get_pt_root_gpa().as_usize(),
        };
        info.rip = entry_point.as_usize();
        info.rsp = 0;
        info.rsi = boot_params.as_usize();
        info.loaded = true;
        manifest.guest_info = info;

        manifest
    }
}

fn build_bootparams<T: MemoryColoring + Clone>(memory_map: &PartitionedMemoryMap<T>) -> BootParams {
    let mut boot_params = BootParams::default();
    boot_params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    boot_params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    boot_params.hdr.header = KERNEL_HDR_MAGIC;
    boot_params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;

    // The initramfs is embedded so not sure we need to do any of that
    //boot_params.hdr.ramdisk_image = ramdisk addr;
    //boot_params.hdr.ramdisk_size = ramdisk size;

    log::info!("Linux boot mem map as construted in stage1");
    let guest_memory_regions = memory_map.build_guest_memory_regions();
    for mr in guest_memory_regions {
        log::info!(
            "Linux boot map: addr 0x{:x}, size 0x{:x}, type {:?}",
            mr.addr.as_usize(),
            mr.size,
            mr.mem_type
        );

        boot_params
            .add_e820_entry(mr)
            .expect("error adding e820 entry");
    }

    boot_params
}
