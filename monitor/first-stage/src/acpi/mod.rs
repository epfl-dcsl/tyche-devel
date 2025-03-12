//! ACPI Tables Support

mod tables;

use alloc::slice;
use alloc::vec::Vec;
use core::{mem, ptr};

use mmu::frame_allocator::PhysRange;
use mmu::{PtFlag, PtMapper, RangeAllocator};
use stage_two_abi::Device;
use tables::{dmar, McfgItem, Rsdp, SdtHeader};

use crate::mmu::scattered_writer::ScatteredIdMappedBuf;
use crate::vmx::{HostPhysAddr, HostVirtAddr};

/// Hardware configuration info collected from ACPI tables.
#[derive(Default, Debug)]
pub struct AcpiInfo {
    /// MCFG table.
    pub mcfg: Option<Vec<McfgItem>>,
    /// DMAR table, containing I/O MMU configuration.
    pub iommu: Option<Vec<IommuInfo>>,
}

/// Information about I/O MMU.
#[derive(Debug,Clone, Copy)]
pub struct IommuInfo {
    /// Base address of the I/O MMU configuration.
    pub base_address: HostPhysAddr,
    /// Size of the I/O MMU configuration, in bytes.
    pub size: usize,
}

/// ACPI 5.2.12.19, Table 5.43 "Multiprocessor Wakeup Structure"
#[repr(C, packed)]
pub struct MultiprocessorWakeupEntry {
    entry_type: u8,
    entry_length: u8,
    mailbox_version: u16,
    _reserved: u32,
    mailbox_address: u64,
}

/// ACPI 5.2.12.19, Table 5.44 "Multiprocessor Wakeup Mailbox Structure"
#[repr(C, packed)]
pub struct MultiprocessorWakeupMailbox {
    command: u16,
    _reserved: u16,
    apic_id: u32,
    wakeup_vector: u64,
    _reserved_for_os: [u8; 2032],
    _reserved_for_fw: [u8; 2048],
}

unsafe fn as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts((p as *const T) as *const u8, ::core::mem::size_of::<T>())
}

impl AcpiInfo {
    /// Read ACPI info from the RSDP pointer.
    ///
    /// SAFETY: The pointer must point to a well formed RSDP table.
    pub unsafe fn from_rsdp(rsdp_ptr: u64, physical_memory_offset: HostVirtAddr) -> Self {
        // Get RSDP virtual address
        let rsdp = &*((rsdp_ptr + physical_memory_offset.as_u64()) as *const Rsdp);
        rsdp.check().expect("Invalid RSDP checksum");
        if rsdp.revision == 0 {
            log::warn!("Missing XSDT");
            return AcpiInfo::default();
        }

        // Parse the XSDT
        let xsdt_ptr = (rsdp.xsdt_address + physical_memory_offset.as_u64()) as *const u8;
        let xsdt_header = &*(xsdt_ptr as *const SdtHeader);
        let lenght = xsdt_header.length as usize;

        // Iterate over table entries
        let mut table_ptr = xsdt_ptr.offset(mem::size_of::<SdtHeader>() as isize);
        let mut acpi_info = AcpiInfo::default();
        while table_ptr < xsdt_ptr.offset(lenght as isize) {
            let table_addr = ptr::read_unaligned(table_ptr as *const u64);
            acpi_info.handle_table(table_addr, physical_memory_offset);
            table_ptr = table_ptr.offset(mem::size_of::<u64>() as isize);
        }

        acpi_info
    }

    /// this will change the magic signature of the `DMAR` table to `XXXX`, effectively disabling it
    pub unsafe fn invalidate_dmar(rsdp_ptr: u64, physical_memory_offset: HostVirtAddr) {
        // Get RSDP virtual address
        let rsdp = &*((rsdp_ptr + physical_memory_offset.as_u64()) as *const Rsdp);
        rsdp.check().expect("Invalid RSDP checksum");
        if rsdp.revision == 0 {
            panic!("Missing XSDT");
        }

        // Parse the XSDT
        let xsdt_ptr = (rsdp.xsdt_address + physical_memory_offset.as_u64()) as *const u8;
        let xsdt_header = &*(xsdt_ptr as *const SdtHeader);
        let lenght = xsdt_header.length as usize;

        //Instead of messing with the table structure, we just change the magic bytes, that identify the DMAR section
        //Linux will ignore the "unknown" section
        let invalidate_if_dmar = |table_addr: u64| {
            let header = &mut *((table_addr + physical_memory_offset.as_u64()) as *mut SdtHeader);
            if &header.signature != b"DMAR" {
                return;
            }
            header.signature = *b"XXXX";
        };

        // Iterate over table entries
        let mut table_ptr = xsdt_ptr.offset(mem::size_of::<SdtHeader>() as isize);
        while table_ptr < xsdt_ptr.offset(lenght as isize) {
            let table_addr = ptr::read_unaligned(table_ptr as *const u64);
            invalidate_if_dmar(table_addr);
            table_ptr = table_ptr.offset(mem::size_of::<u64>() as isize);
        }
    }

    unsafe fn handle_table(&mut self, table_addr: u64, physical_memory_offset: HostVirtAddr) {
        let header = &*((table_addr + physical_memory_offset.as_u64()) as *const SdtHeader);
        match &header.signature {
            b"MCFG" => self.handle_mcfg_table(header),
            b"DMAR" => self.handle_dmar_table(header),
            _ => {
                log::info!(
                    "ACPI: unknown table '{}'",
                    core::str::from_utf8(&header.signature)
                        .expect("Failed to parse table signature")
                );
            }
        }
    }

    unsafe fn handle_mcfg_table(&mut self, header: &SdtHeader) {
        log::info!("ACPI: parsing 'MCFG' table");
        header.verify_checksum().expect("Invalid MCFG checksum");

        // Table items start at offset 44.
        // See https://wiki.osdev.org/PCI_Express
        let item_ptr = ((header as *const _) as *const u8).offset(44);
        let mut item_ptr = item_ptr as *const McfgItem;
        let table_end = ((header as *const _) as *const u8).offset(header.length as isize);
        let table_end = table_end as *const McfgItem;
        let mut items = Vec::new();
        while item_ptr < table_end {
            let item = ptr::read_unaligned(item_ptr);
            items.push(item);

            item_ptr = item_ptr.offset(1);
        }

        self.mcfg = Some(items);
    }

    unsafe fn handle_dmar_table(&mut self, header: &SdtHeader) {
        log::info!("ACPI: parsing 'DMAR' table");
        header.verify_checksum().expect("Invalid DMAR checksum");

        let table_ptr = (header as *const _) as *const u8;
        let table_end = table_ptr.offset(header.length as isize);
        let mut remap_struct_ptr = table_ptr.offset(mem::size_of::<dmar::Header>() as isize);
        let mut iommus = Vec::new();
        while remap_struct_ptr < table_end {
            let remap_header = &*(remap_struct_ptr as *const dmar::RemappingHeader);
            match remap_header.typ {
                0 => {
                    let iommu = self
                        .handle_dmar_drhd(&*(remap_struct_ptr as *const dmar::DmaRemappingHwUnit));
                    iommus.push(iommu);
                }
                _ => {
                    log::info!("  Unknown DMAR type: {}", remap_header.typ);
                }
            }

            remap_struct_ptr = remap_struct_ptr.offset(remap_header.length as isize);
        }

        self.iommu = Some(iommus);
    }

    unsafe fn handle_dmar_drhd(&mut self, remap_unit: &dmar::DmaRemappingHwUnit) -> IommuInfo {
        if remap_unit.flags & 0b1 == 0 {
            // Only the specified devices are remapped.

            let unit_ptr = (remap_unit as *const _) as *const u8;
            let unit_end = unit_ptr.offset(remap_unit.header.length as isize);
            let mut device_scope_ptr =
                unit_ptr.offset(mem::size_of::<dmar::DmaRemappingHwUnit>() as isize);
            while device_scope_ptr < unit_end {
                let device_scope = &*(device_scope_ptr as *const dmar::DeviceScope);
                if device_scope.length != 8 {
                    todo!("Handle arbitrary PCI device path");
                }

                // We assume a single path here
                let path = &*(device_scope_ptr.offset(mem::size_of::<dmar::DeviceScope>() as isize)
                    as *const dmar::Path);
                log::info!(
                    "  PCI: {:02x}:{:02x}.{} - len: {} - type: {}",
                    device_scope.start_bus,
                    path.device_number,
                    path.function_number,
                    device_scope.length,
                    device_scope.typ
                );

                device_scope_ptr = device_scope_ptr.offset(device_scope.length as isize);
            }
        }
        let base_address = HostPhysAddr::new(remap_unit.base_address as usize);
        let size = 1 << ((remap_unit.size & 0b1111) + 12);
        IommuInfo { base_address, size }
    }

    fn allocate_mailbox(
        &self,
        allocator: &impl RangeAllocator,
        pt_mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
    ) -> u64 {
        // Allocate a page for the mailbox structure
        let mailbox = allocator
            .allocate_frame()
            .expect("New Mailbox Page Allocation")
            .zeroed();
        pt_mapper.map_range(
            allocator,
            HostVirtAddr::new(mailbox.phys_addr.as_usize()),
            mailbox.phys_addr,
            0x1000,
            PtFlag::WRITE | PtFlag::PRESENT | PtFlag::USER,
        );

        mailbox.phys_addr.as_u64()
    }

    pub unsafe fn add_mp_wakeup_entry(
        &mut self,
        rsdp_ptr: u64,
        physical_memory_offset: HostVirtAddr,
        allocator: &impl RangeAllocator,
        pt_mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
    ) -> u64 {
        // Get RSDP virtual address
        let rsdp = &*((rsdp_ptr + physical_memory_offset.as_u64()) as *const Rsdp);
        rsdp.check().expect("Invalid RSDP checksum");
        if rsdp.revision == 0 {
            panic!("Missing XSDT");
        }

        // Parse the XSDT
        let xsdt_ptr = (rsdp.xsdt_address + physical_memory_offset.as_u64()) as *const u8;
        let xsdt_header = &*(xsdt_ptr as *const SdtHeader);
        let length = xsdt_header.length as usize;

        // Iterate over table entries
        let mut table_ptr = xsdt_ptr.offset(mem::size_of::<SdtHeader>() as isize);
        let mut mailbox: u64 = 0;

        while table_ptr < xsdt_ptr.offset(length as isize) {
            let table_addr = ptr::read_unaligned(table_ptr as *const u64);
            let header = &*((table_addr + physical_memory_offset.as_u64()) as *const SdtHeader);

            match &header.signature {
                b"APIC" => {
                    mailbox = self.allocate_mailbox(allocator, pt_mapper);
                    log::info!("MP Wakeup Mailbox Address: {:#x}", mailbox);
                    let entry =
                        self.add_madt_mp_wakeup_entry(header, mailbox, allocator, pt_mapper);
                    (table_ptr as *mut u64).write_unaligned(entry.as_u64());
                    break;
                }
                _ => (),
            };
            table_ptr = table_ptr.offset(mem::size_of::<u64>() as isize);
        }

        let checksum = xsdt_header.compute_checksum();
        let offset: usize = mem::size_of::<u32>() + mem::size_of::<u32>() + mem::size_of::<u8>();
        ((xsdt_ptr as usize + offset) as *mut u8).write_unaligned(checksum as u8);

        xsdt_header
            .verify_checksum()
            .expect("Invalid XSDT Checksum");

        mailbox
    }

    pub unsafe fn add_madt_mp_wakeup_entry(
        &mut self,
        header: &SdtHeader,
        mailbox: u64,
        allocator: &impl RangeAllocator,
        mapper: &mut PtMapper<HostPhysAddr, HostVirtAddr>,
    ) -> HostVirtAddr {
        log::info!("Adding the MP Wakeup Entry to MADT Table");

        let table_ptr = (header as *const _) as *const u8;
        let table_end = table_ptr.offset(header.length as isize);
        let old_table_len = table_end as usize - table_ptr as usize;

        log::info!(
            "MADT Table Pointer={:p}, MADT Table End={:p}, MADT Table Length={}",
            table_ptr,
            table_end,
            old_table_len
        );
        let mut madt_ranges: Vec<PhysRange> = Vec::new();
        let store_cb = |pr: PhysRange| {
            madt_ranges.push(pr);
        };
        // Allocate a new memory range for MADT Table
        allocator
            .allocate_range(old_table_len * 2, store_cb)
            .expect("New MADT Allocation");
        let madt_vaddr = HostVirtAddr::new(madt_ranges[0].start.as_usize());
        mapper
            .map_range_scattered(
                allocator,
                madt_vaddr,
                &madt_ranges,
                old_table_len,
                PtFlag::WRITE | PtFlag::PRESENT | PtFlag::USER,
            )
            .expect("error mapping madt");

        let mut new_madt_location =
            ScatteredIdMappedBuf::new(madt_ranges, allocator.get_physical_offset().as_usize(), 0);
        // Copy MADT Table to the newly allocated range
        new_madt_location
            .write(slice::from_raw_parts(table_ptr as *const u8, old_table_len))
            .expect("failed to copy madt table to new location");

        // Create the new AP Wakeup Entry
        let wakeup = MultiprocessorWakeupEntry {
            entry_type: 0x10,
            entry_length: 16,
            mailbox_version: 0,
            _reserved: 0,
            mailbox_address: mailbox,
        };

        let wakeup_bytes: &[u8] = unsafe { as_u8_slice(&wakeup) };

        // Copy the new entry to the new MADT table
        new_madt_location
            .write(&wakeup_bytes[..wakeup.entry_length as usize])
            .expect("failed to copy new entry to madt table");

        // Modify the length
        ((madt_vaddr + mem::size_of::<u32>()).as_usize() as *mut u32)
            .write_unaligned(header.length + wakeup.entry_length as u32);
        let header = &*(madt_vaddr.as_usize() as *const SdtHeader);
        let checksum = header.compute_checksum();
        let offset: usize = mem::size_of::<u32>() + mem::size_of::<u32>() + mem::size_of::<u8>();
        ((madt_vaddr + offset).as_usize() as *mut u8).write_unaligned(checksum as u8);
        header
            .verify_checksum()
            .expect("New MADT Entry Checksum Error");
        madt_vaddr
    }

    pub fn enumerate_mcfg_item(
        &self,
        item: &McfgItem,
        physical_memory_offset: HostVirtAddr,
    ) -> Vec<Device> {
        let mut result = Vec::new();
        let base = item.base_address;
        for bus in item.start_bus..=item.end_bus {
            for device in 0u8..=31 {
                for func in 0u8..=7 {
                    let addr = base
                        + ((bus as u64) << 20)
                        + ((device as u64) << 15)
                        + ((func as u64) << 12);
                    let vendor_id = (addr + physical_memory_offset.as_u64()) as *const u16;
                    unsafe {
                        //The vendor_id is valid, parse the bars.
                        if *vendor_id != 0xffff {
                            let bars = self.parse_bars(vendor_id as *mut u32);
                            for (start, size, is_mem) in bars {
                                if start == 0 || size == 0 {
                                    continue;
                                }
                                result.push(Device {
                                    start,
                                    size,
                                    is_mem,
                                });
                            }
                        }
                    }
                }
            }
        }
        result
    }

    // The code follows the documentation from: https://wiki.osdev.org/PCI#Address_and_size_of_the_BAR
    pub unsafe fn parse_bars(&self, config_space: *mut u32) -> [(u64, u64, bool); 6] {
        const BAR_OFFSET: usize = 4; // BARs start at offset 0x10 in the config space

        let mut bars: [(u64, u64, bool); 6] = [(0, 0, false); 6];
        let mut offset = BAR_OFFSET;

        let _reg2 = core::ptr::read_volatile(config_space.add(2));
        let reg3 = core::ptr::read_volatile(config_space.add(3));

        // The 0x80 mask represents a multifunction device.
        let num_bars = match (reg3 >> 16) & 0xFF {
            // General device.
            0x0 | 0x80 => 6,
            // PCI-to-PCI bridge.
            0x1 | 0x81 => 2,
            // PCI-toCardbus bridge.
            0x2 | 0x82 => {
                log::info!("PCI-toCardbus.. ignore?");
                return bars;
            }
            _ => {
                panic!(
                    "Invalid header type in PCI config space {:#x}",
                    ((reg3 >> 16) & 0xFF)
                );
            }
        };

        for i in 0..num_bars {
            // Read the current BAR
            let original_value = core::ptr::read_volatile(config_space.add(offset) as *const u32);

            // Skip unused BARs
            if original_value == 0 {
                offset += 1; // Move to the next BAR
                continue;
            }

            // Check if the BAR is memory mapped or io.
            let is_mem = (original_value & 0b1) == 0;

            // Check if the BAR is 64-bit or 32-bit
            let is_64_bit = is_mem && ((original_value & 0b110) == 0b100);

            // Write 0xFFFFFFFF to the BAR
            core::ptr::write_volatile(config_space.add(offset), 0xFFFFFFFF);

            // Read back the size mask
            let size_mask = core::ptr::read_volatile(config_space.add(offset) as *const u32);

            // Restore the original value
            core::ptr::write_volatile(config_space.add(offset), original_value);

            // Compute the size by inverting the size mask and aligning it
            let size = if is_mem {
                !(size_mask & 0xFFFFFFF0) + 1
            } else {
                (!size_mask & 0xFFFF) + 1
            };

            // Extract the base address (only relevant bits)
            let mut base_address = if is_mem {
                u64::from(original_value & 0xFFFFFFF0)
            } else {
                u64::from(original_value & 0xFFFFFFFC)
            };

            if is_64_bit {
                // For 64-bit BARs, read the high 32 bits
                let high_value =
                    core::ptr::read_volatile(config_space.add(offset + 1) as *const u32);
                base_address |= u64::from(high_value & 0xFFFFFFFF) << 32;

                // Increment the offset to skip the next BAR as it's part of this one
                offset += 1;
            }

            bars[i] = (base_address, size as u64, is_mem);
            offset += 1; // Move to the next BAR
        }
        bars
    }
}
