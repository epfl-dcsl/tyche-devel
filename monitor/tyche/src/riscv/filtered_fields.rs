use riscv_utils::PAGING_MODE_SV48;

use crate::riscv::context::ContextRiscv;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum RiscVField {
    Medeleg = 0x00004004,
    Satp = 0x00006802,
    Sp = 0x0000681c,
    Mepc = 0x0000681e,
}

impl RiscVField {
    pub fn from_usize(v: usize) -> Option<Self> {
        match v {
            0x00004004 => Some(Self::Medeleg),
            0x00006802 => Some(Self::Satp),
            0x0000681c => Some(Self::Sp),
            0x0000681e => Some(Self::Mepc),
            _ => {
                log::error!("Unknown field value, you should check that {:x}", v);
                None
            }
        }
    }
    pub fn is_valid(v: usize) -> bool {
        Self::from_usize(v).is_some()
    }

    #[inline]
    pub fn raw(&self) -> usize {
        *self as usize
    }

    pub fn set(&self, context: &mut ContextRiscv, value: usize) {
        match *self {
            Self::Medeleg => {
                context.medeleg = value;
                log::debug!("Setting medeleg to {:x}", context.medeleg);
            }
            Self::Satp => {
                context.satp = (value >> 12) | PAGING_MODE_SV48;
                log::debug!("Setting satp to {:x}", context.satp);
            }
            Self::Sp => {
                context.sp = value;
                log::debug!("Setting sp to {:x}", context.sp);
            }
            Self::Mepc => {
                context.mepc = value - 0x4; //Todo: This is a temporary hack - because before returning
                                            //there's an mepc+4.
                log::debug!("Setting mepc to {:x}", context.mepc);
            }
        }
    }

    pub fn get(&self, context: &ContextRiscv) -> usize {
        match *self {
            Self::Medeleg => context.medeleg,
            Self::Satp => context.satp,
            Self::Sp => context.sp,
            Self::Mepc => context.mepc,
        }
    }
}
