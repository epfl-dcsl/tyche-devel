//! ACPI tables definitions

use core::slice;

// —————————————————————————————————— RSDP —————————————————————————————————— //

/// The Root System Description Pointer.
#[repr(C, packed)]
pub struct Rsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,

    // These fields are only valid for ACPI Version 2.0 and greater,
    // i.e. revision > 0.
    pub length: u32,
    pub xsdt_address: u64,
    pub ext_checksum: u8,
    pub reserved: [u8; 3],
}

impl Rsdp {
    /// Checks that the RSDP table is valid by computing the checksum.
    pub fn check(&self) -> Result<(), ()> {
        let mut sum: u64 = 0;

        for byte in self.signature {
            sum += byte as u64;
        }
        for byte in self.oem_id {
            sum += byte as u64;
        }
        for byte in self.rsdt_address.to_le_bytes() {
            sum += byte as u64;
        }
        sum += self.checksum as u64;
        sum += self.revision as u64;

        if self.revision > 0 {
            for byte in self.length.to_le_bytes() {
                sum += byte as u64;
            }
            for byte in self.xsdt_address.to_le_bytes() {
                sum += byte as u64;
            }
            for byte in self.reserved {
                sum += byte as u64;
            }
            sum += self.ext_checksum as u64;
        }

        if sum & 0xFF == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

// ————————————————————————————— Shared Header —————————————————————————————— //

/// Shared header for System Description Tables.
#[derive(Debug)]
#[repr(C, packed)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

impl SdtHeader {
    pub unsafe fn compute_checksum(&self) -> u64 {
        let table = slice::from_raw_parts((self as *const _) as *const u8, self.length as usize);
        let mut checksum: u64 = 0;
        for byte in table {
            checksum += *byte as u64;
        }

        let header = &*(self as *const SdtHeader);
        checksum -= header.checksum as u64;

        0x100 - (checksum & 0xFF)
    }
    pub unsafe fn verify_checksum(&self) -> Result<(), ()> {
        // We trust that the table content is valid here, in particular that the length correspond
        // to the real length of the table and therefore entirely reside in accessible memory.
        let table = slice::from_raw_parts((self as *const _) as *const u8, self.length as usize);
        let mut checksum: u64 = 0;
        for byte in table {
            checksum += *byte as u64;
        }

        // The table is valid only if the last 8 bits of the checksum are 0
        match checksum & 0xFF {
            0 => Ok(()),
            _ => Err(()),
        }
    }
}

// —————————————————————————————————— MCFG —————————————————————————————————— //

/// ACPI MCFG table items, describing configuration address spaces of PCIe devices.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct McfgItem {
    /// Base address of the configuration address space.
    pub base_address: u64,
    /// PCI segment group number.
    pub segment_group: u16,
    /// Start PCI bus number decoded by this host bridge.
    pub start_bus: u8,
    /// End PCI bus number decoded by this host bridge.
    pub end_bus: u8,
    // Reserved.
    pub reserved: u32,
}

// —————————————————————————————————— DMAR —————————————————————————————————— //

pub mod dmar {
    //! DMA Remapping Reporting (DMAR) ACPI table.
    //!
    //! This table describes the I/O MMUs and the devices they oversee.
    //!
    //! See documentation in Intel Virtualization Technology for Direct I/O manual (VT-d), section
    //! 8 (BIOS Considerations).

    use super::SdtHeader;

    /// DMA Remapping reporting structure.
    #[repr(C, packed)]
    pub struct Header {
        pub header: SdtHeader,
        /// Maximum DMA physical addressability.
        pub host_addr_width: u8,
        /// DMA Remapping feature flags.
        ///
        /// - Bit 0: if set platform support interrupt remapping.
        /// - Bit 1: if set the firmware kindly ask not to use x2APIC.
        /// - Bit 2: ?
        /// - Bit 3 to 7: Reserved (0)
        pub flags: u8,
        _reserved: [u8; 10],
    }

    /// Header of Remapping structures found in the DMAR.
    pub struct RemappingHeader {
        /// Structure type.
        ///
        /// - 1: Dma Remapping Hardware Unit
        pub typ: u16,
        pub length: u16,
    }

    /// DMA Remapping Hardware Unit Definition.
    #[repr(C, packed)]
    pub struct DmaRemappingHwUnit {
        pub header: RemappingHeader,
        /// Remapping unit flags.
        ///
        /// - Bit 0: if cleared this unit only remap devices defined in the device scope blocks. If
        ///          set to 1 this unit remap all devices not already remapped by other units in
        ///          the current segment.
        /// - Bit 1 to 7: Reserved.
        pub flags: u8,
        /// Size of remapping hardware registers, in pages.
        ///
        /// - Bits 3:0 indicates the number of 4kb pages in power of two of the register region. If
        ///   value is N, the region is 2^N pages, i.e. 2^(N + 12) bytes.
        pub size: u8,
        /// PCI segment associated with this unit.
        pub segment_number: u16,
        /// Register base address.
        pub base_address: u64,
    }

    /// DMA remapping unit scope.
    #[repr(C, packed)]
    pub struct DeviceScope {
        /// type of scipe.
        ///
        /// - 0x01: pci endpoint device.
        /// - 0x02: pci sub-hierarchy.
        /// - 0x03: ioapic.
        /// - 0x04: msi_capable_hpet.
        /// - 0x05: acpi_namespace_device.
        pub typ: u8,
        pub length: u8,
        /// flags.
        pub flags: u8,
        _reserved: u8,
        /// device id, as it appears in other acpi tables.
        pub enumeration_id: u8,
        /// start bus number of the device range.
        pub start_bus: u8,
    }

    /// Path to a PCI device on a given bus.
    pub struct Path {
        pub device_number: u8,
        pub function_number: u8,
    }
}
