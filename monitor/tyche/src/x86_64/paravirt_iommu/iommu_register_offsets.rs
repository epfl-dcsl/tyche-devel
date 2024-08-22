use core::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DmarRegister {
    /// Arch version supported by this IOMMU
    VerReg = 0x0,
    /// Hardware supported capabilities
    CapReg = 0x8,
    /// Extended capabilities supported
    EcapReg = 0x10,
    /// Global command register
    GcmdReg = 0x18,
    /// Global status register
    GstsReg = 0x1c,
    /// Root entry table
    RtaddrReg = 0x20,
    /// Context command reg
    CcmdReg = 0x28,
    /// Fault Status register
    FstsReg = 0x34,
    /// Fault control register
    FectlReg = 0x38,
    /// Fault event interrupt data register
    FedataReg = 0x3c,
    /// Fault event interrupt addr register
    FeaddrReg = 0x40,
    /// Upper address register
    FeuaddrReg = 0x44,
    /// Advanced Fault control
    AflogReg = 0x58,
    /// Enable Protected Memory Region
    PmenReg = 0x64,
    /// PMRR Low addr
    PlmbaseReg = 0x68,
    /// PMRR low limit
    PlmlimitReg = 0x6c,
    /// pmrr high base addr
    PhmbaseReg = 0x70,
    /// pmrr high limit
    PhmlimitReg = 0x78,
    /// Invalidation queue head register
    IqhReg = 0x80,
    /// Invalidation queue tail register
    IqtReg = 0x88,
    /// Invalidation queue addr register
    IqaReg = 0x90,
    /// Invalidation complete status register
    IcsReg = 0x9c,
    /// Invalidation queue error record register
    IqerReg = 0xb0,
    /// Interrupt remapping table addr register
    IrtaReg = 0xb8,
    /// Page request queue head register
    PqhReg = 0xc0,
    /// Page request queue tail register
    PqtReg = 0xc8,
    /// Page request queue address register
    PqaReg = 0xd0,
    /// Page request status register
    PrsReg = 0xdc,
    /// Page request event control register
    PectlReg = 0xe0,
    /// Page request event interrupt data register
    PedataReg = 0xe4,
    /// Page request event interrupt addr register
    PeaddrReg = 0xe8,
    /// Page request event Upper address register
    PeuaddrReg = 0xec,
    /// MTRR capability register
    MtrrcapReg = 0x100,
    /// MTRR default type register
    MtrrdefReg = 0x108,
    /// MTRR Fixed range registers
    MtrrFix64k00000Reg = 0x120,
    /// MTRR Fixed range registers
    MtrrFix16k80000Reg = 0x128,
    /// MTRR Fixed range registers
    MtrrFix16kA0000Reg = 0x130,
    /// MTRR Fixed range registers
    MtrrFix4kC0000Reg = 0x138,
    /// MTRR Fixed range registers
    MtrrFix4kC8000Reg = 0x140,
    /// MTRR Fixed range registers
    MtrrFix4kD0000Reg = 0x148,
    /// MTRR Fixed range registers
    MtrrFix4kD8000Reg = 0x150,
    /// MTRR Fixed range registers
    MtrrFix4kE0000Reg = 0x158,
    /// MTRR Fixed range registers
    MtrrFix4kE8000Reg = 0x160,
    /// MTRR Fixed range registers
    MtrrFix4kF0000Reg = 0x168,
    /// MTRR Fixed range registers
    MtrrFix4kF8000Reg = 0x170,
    /// MTRR Variable range registers
    MtrrPhysbase0Reg = 0x180,
    /// MTRR Variable range registers
    MtrrPhysmask0Reg = 0x188,
    /// MTRR Variable range registers
    MtrrPhysbase1Reg = 0x190,
    /// MTRR Variable range registers
    MtrrPhysmask1Reg = 0x198,
    /// MTRR Variable range registers
    MtrrPhysbase2Reg = 0x1a0,
    /// MTRR Variable range registers
    MtrrPhysmask2Reg = 0x1a8,
    /// MTRR Variable range registers
    MtrrPhysbase3Reg = 0x1b0,
    /// MTRR Variable range registers
    MtrrPhysmask3Reg = 0x1b8,
    /// MTRR Variable range registers
    MtrrPhysbase4Reg = 0x1c0,
    /// MTRR Variable range registers
    MtrrPhysmask4Reg = 0x1c8,
    /// MTRR Variable range registers
    MtrrPhysbase5Reg = 0x1d0,
    /// MTRR Variable range registers
    MtrrPhysmask5Reg = 0x1d8,
    /// MTRR Variable range registers
    MtrrPhysbase6Reg = 0x1e0,
    /// MTRR Variable range registers
    MtrrPhysmask6Reg = 0x1e8,
    /// MTRR Variable range registers
    MtrrPhysbase7Reg = 0x1f0,
    /// MTRR Variable range registers
    MtrrPhysmask7Reg = 0x1f8,
    /// MTRR Variable range registers
    MtrrPhysbase8Reg = 0x200,
    /// MTRR Variable range registers
    MtrrPhysmask8Reg = 0x208,
    /// MTRR Variable range registers
    MtrrPhysbase9Reg = 0x210,
    /// MTRR Variable range registers
    MtrrPhysmask9Reg = 0x218,
    /// Virtual command capability register
    VccapReg = 0xe30,
    /// Virtual command register
    VcmdReg = 0xe00,
    /// Virtual command response register
    VcrspReg = 0xe10,
}

impl TryFrom<usize> for DmarRegister {
    type Error = &'static str;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let reg = match value {
            0x0 => DmarRegister::VerReg,
            0x8 => DmarRegister::CapReg,
            0x10 => DmarRegister::EcapReg,
            0x18 => DmarRegister::GcmdReg,
            0x1c => DmarRegister::GstsReg,
            0x20 => DmarRegister::RtaddrReg,
            0x28 => DmarRegister::CcmdReg,
            0x34 => DmarRegister::FstsReg,
            0x38 => DmarRegister::FectlReg,
            0x3c => DmarRegister::FedataReg,
            0x40 => DmarRegister::FeaddrReg,
            0x44 => DmarRegister::FeuaddrReg,
            0x58 => DmarRegister::AflogReg,
            0x64 => DmarRegister::PmenReg,
            0x68 => DmarRegister::PlmbaseReg,
            0x6c => DmarRegister::PlmlimitReg,
            0x70 => DmarRegister::PhmbaseReg,
            0x78 => DmarRegister::PhmlimitReg,
            0x80 => DmarRegister::IqhReg,
            0x88 => DmarRegister::IqtReg,
            0x90 => DmarRegister::IqaReg,
            0x9c => DmarRegister::IcsReg,
            0xb0 => DmarRegister::IqerReg,
            0xb8 => DmarRegister::IrtaReg,
            0xc0 => DmarRegister::PqhReg,
            0xc8 => DmarRegister::PqtReg,
            0xd0 => DmarRegister::PqaReg,
            0xdc => DmarRegister::PrsReg,
            0xe0 => DmarRegister::PectlReg,
            0xe4 => DmarRegister::PedataReg,
            0xe8 => DmarRegister::PeaddrReg,
            0xec => DmarRegister::PeuaddrReg,
            0x100 => DmarRegister::MtrrcapReg,
            0x108 => DmarRegister::MtrrdefReg,
            0x120 => DmarRegister::MtrrFix64k00000Reg,
            0x128 => DmarRegister::MtrrFix16k80000Reg,
            0x130 => DmarRegister::MtrrFix16kA0000Reg,
            0x138 => DmarRegister::MtrrFix4kC0000Reg,
            0x140 => DmarRegister::MtrrFix4kC8000Reg,
            0x148 => DmarRegister::MtrrFix4kD0000Reg,
            0x150 => DmarRegister::MtrrFix4kD8000Reg,
            0x158 => DmarRegister::MtrrFix4kE0000Reg,
            0x160 => DmarRegister::MtrrFix4kE8000Reg,
            0x168 => DmarRegister::MtrrFix4kF0000Reg,
            0x170 => DmarRegister::MtrrFix4kF8000Reg,
            0x180 => DmarRegister::MtrrPhysbase0Reg,
            0x188 => DmarRegister::MtrrPhysmask0Reg,
            0x190 => DmarRegister::MtrrPhysbase1Reg,
            0x198 => DmarRegister::MtrrPhysmask1Reg,
            0x1a0 => DmarRegister::MtrrPhysbase2Reg,
            0x1a8 => DmarRegister::MtrrPhysmask2Reg,
            0x1b0 => DmarRegister::MtrrPhysbase3Reg,
            0x1b8 => DmarRegister::MtrrPhysmask3Reg,
            0x1c0 => DmarRegister::MtrrPhysbase4Reg,
            0x1c8 => DmarRegister::MtrrPhysmask4Reg,
            0x1d0 => DmarRegister::MtrrPhysbase5Reg,
            0x1d8 => DmarRegister::MtrrPhysmask5Reg,
            0x1e0 => DmarRegister::MtrrPhysbase6Reg,
            0x1e8 => DmarRegister::MtrrPhysmask6Reg,
            0x1f0 => DmarRegister::MtrrPhysbase7Reg,
            0x1f8 => DmarRegister::MtrrPhysmask7Reg,
            0x200 => DmarRegister::MtrrPhysbase8Reg,
            0x208 => DmarRegister::MtrrPhysmask8Reg,
            0x210 => DmarRegister::MtrrPhysbase9Reg,
            0x218 => DmarRegister::MtrrPhysmask9Reg,
            0xe30 => DmarRegister::VccapReg,
            0xe00 => DmarRegister::VcmdReg,
            0xe10 => DmarRegister::VcrspReg,
            _ => {
                log::error!("DmarRegister::try_from, invalid value {:x}", value);
                return Err("Unknown register address");
            }
        };
        return Ok(reg);
    }
}

impl Display for DmarRegister {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let v = match self {
            DmarRegister::VerReg => "DmarRegister::VerReg",
            DmarRegister::CapReg => "DmarRegister::CapReg",
            DmarRegister::EcapReg => "DmarRegister::EcapReg",
            DmarRegister::GcmdReg => "DmarRegister::GcmdReg",
            DmarRegister::GstsReg => "DmarRegister::GstsReg",
            DmarRegister::RtaddrReg => "DmarRegister::RtaddrReg",
            DmarRegister::CcmdReg => "DmarRegister::CcmdReg",
            DmarRegister::FstsReg => "DmarRegister::FstsReg",
            DmarRegister::FectlReg => "DmarRegister::FectlReg",
            DmarRegister::FedataReg => "DmarRegister::FedataReg",
            DmarRegister::FeaddrReg => "DmarRegister::FeaddrReg",
            DmarRegister::FeuaddrReg => "DmarRegister::FeuaddrReg",
            DmarRegister::AflogReg => "DmarRegister::AflogReg",
            DmarRegister::PmenReg => "DmarRegister::PmenReg",
            DmarRegister::PlmbaseReg => "DmarRegister::PlmbaseReg",
            DmarRegister::PlmlimitReg => "DmarRegister::PlmlimitReg",
            DmarRegister::PhmbaseReg => "DmarRegister::PhmbaseReg",
            DmarRegister::PhmlimitReg => "DmarRegister::PhmlimitReg",
            DmarRegister::IqhReg => "DmarRegister::IqhReg",
            DmarRegister::IqtReg => "DmarRegister::IqtReg",
            DmarRegister::IqaReg => "DmarRegister::IqaReg",
            DmarRegister::IcsReg => "DmarRegister::IcsReg",
            DmarRegister::IqerReg => "DmarRegister::IqerReg",
            DmarRegister::IrtaReg => "DmarRegister::IrtaReg",
            DmarRegister::PqhReg => "DmarRegister::PqhReg",
            DmarRegister::PqtReg => "DmarRegister::PqtReg",
            DmarRegister::PqaReg => "DmarRegister::PqaReg",
            DmarRegister::PrsReg => "DmarRegister::PrsReg",
            DmarRegister::PectlReg => "DmarRegister::PectlReg",
            DmarRegister::PedataReg => "DmarRegister::PedataReg",
            DmarRegister::PeaddrReg => "DmarRegister::PeaddrReg",
            DmarRegister::PeuaddrReg => "DmarRegister::PeuaddrReg",
            DmarRegister::MtrrcapReg => "DmarRegister::MtrrcapReg",
            DmarRegister::MtrrdefReg => "DmarRegister::MtrrdefReg",
            DmarRegister::MtrrFix64k00000Reg => "DmarRegister::MtrrFix64k00000Reg",
            DmarRegister::MtrrFix16k80000Reg => "DmarRegister::MtrrFix16k80000Reg",
            DmarRegister::MtrrFix16kA0000Reg => "DmarRegister::MtrrFix16kA0000Reg",
            DmarRegister::MtrrFix4kC0000Reg => "DmarRegister::MtrrFix4kC0000Reg",
            DmarRegister::MtrrFix4kC8000Reg => "DmarRegister::MtrrFix4kC8000Reg",
            DmarRegister::MtrrFix4kD0000Reg => "DmarRegister::MtrrFix4kD0000Reg",
            DmarRegister::MtrrFix4kD8000Reg => "DmarRegister::MtrrFix4kD8000Reg",
            DmarRegister::MtrrFix4kE0000Reg => "DmarRegister::MtrrFix4kE0000Reg",
            DmarRegister::MtrrFix4kE8000Reg => "DmarRegister::MtrrFix4kE8000Reg",
            DmarRegister::MtrrFix4kF0000Reg => "DmarRegister::MtrrFix4kF0000Reg",
            DmarRegister::MtrrFix4kF8000Reg => "DmarRegister::MtrrFix4kF8000Reg",
            DmarRegister::MtrrPhysbase0Reg => "DmarRegister::MtrrPhysbase0Reg",
            DmarRegister::MtrrPhysmask0Reg => "DmarRegister::MtrrPhysmask0Reg",
            DmarRegister::MtrrPhysbase1Reg => "DmarRegister::MtrrPhysbase1Reg",
            DmarRegister::MtrrPhysmask1Reg => "DmarRegister::MtrrPhysmask1Reg",
            DmarRegister::MtrrPhysbase2Reg => "DmarRegister::MtrrPhysbase2Reg",
            DmarRegister::MtrrPhysmask2Reg => "DmarRegister::MtrrPhysmask2Reg",
            DmarRegister::MtrrPhysbase3Reg => "DmarRegister::MtrrPhysbase3Reg",
            DmarRegister::MtrrPhysmask3Reg => "DmarRegister::MtrrPhysmask3Reg",
            DmarRegister::MtrrPhysbase4Reg => "DmarRegister::MtrrPhysbase4Reg",
            DmarRegister::MtrrPhysmask4Reg => "DmarRegister::MtrrPhysmask4Reg",
            DmarRegister::MtrrPhysbase5Reg => "DmarRegister::MtrrPhysbase5Reg",
            DmarRegister::MtrrPhysmask5Reg => "DmarRegister::MtrrPhysmask5Reg",
            DmarRegister::MtrrPhysbase6Reg => "DmarRegister::MtrrPhysbase6Reg",
            DmarRegister::MtrrPhysmask6Reg => "DmarRegister::MtrrPhysmask6Reg",
            DmarRegister::MtrrPhysbase7Reg => "DmarRegister::MtrrPhysbase7Reg",
            DmarRegister::MtrrPhysmask7Reg => "DmarRegister::MtrrPhysmask7Reg",
            DmarRegister::MtrrPhysbase8Reg => "DmarRegister::MtrrPhysbase8Reg",
            DmarRegister::MtrrPhysmask8Reg => "DmarRegister::MtrrPhysmask8Reg",
            DmarRegister::MtrrPhysbase9Reg => "DmarRegister::MtrrPhysbase9Reg",
            DmarRegister::MtrrPhysmask9Reg => "DmarRegister::MtrrPhysmask9Reg",
            DmarRegister::VccapReg => "DmarRegister::VccapReg",
            DmarRegister::VcmdReg => "DmarRegister::VcmdReg",
            DmarRegister::VcrspReg => "DmarRegister::VcrspReg",
        };
        write!(f, "{}", v)
    }
}
