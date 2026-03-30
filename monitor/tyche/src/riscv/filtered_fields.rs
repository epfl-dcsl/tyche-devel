use riscv_utils::{PAGING_MODE_SV39, PAGING_MODE_SV48};

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
            _ => None,
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
                context.satp = (value >> 12) | PAGING_MODE_SV39;
                log::debug!("Setting satp to {:x}", context.satp);
            }
            Self::Sp => {
                let mut val = (value >> 3) << 3; //Forcing it to be 8 bytes aligned.
                context.sp = val;
                log::debug!("Setting sp to {:x}", context.sp);
            }
            Self::Mepc => {
                context.mepc = value - 0x4; //This is because before returning
                                            //there's an mepc+4. A flag can be added to
                                            //determine before returning whether to inc by 4 or
                                            //not. This works for now.
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
