use crate::riscv::monitor::ContextData;

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

    pub fn set(&self, context: &mut ContextData, value: usize) {
        match *self {
            Self::Medeleg => {
                context.medeleg = value;
            }
            Self::Satp => {
                context.satp = value;
            }
            Self::Sp => {
                context.sp = value;
            }
            Self::Mepc => {
                context.mepc = value;
            }
        }
    }

    pub fn get(&self, context: &ContextData) -> usize {
        match *self {
            Self::Medeleg => context.medeleg,
            Self::Satp => context.satp,
            Self::Sp => context.sp,
            Self::Mepc => context.mepc,
        }
    }
}
