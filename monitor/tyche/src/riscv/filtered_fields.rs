use riscv_utils::{PAGING_MODE_SV39, PAGING_MODE_SV48};

use crate::riscv::context::ContextRiscv;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum RiscVField {
    Medeleg = 0x00004004,
    Satp = 0x00006802,
    Sp = 0x0000681c,
    Mepc = 0x0000681e,
    Sepc = 0x00006816,
    Mstatus = 0x00006818,
    A0 = 0xff007000,
    A1 = 0xff007002,
    A2 = 0xff007004,
    A3 = 0xff007006,
    A4 = 0xff007008,
    A5 = 0xff00700a,
    A6 = 0xff00700c,
    A7 = 0xff00700e,
}

impl RiscVField {
    pub fn from_usize(v: usize) -> Option<Self> {
        match v {
            0x00004004 => Some(Self::Medeleg),
            0x00006802 => Some(Self::Satp),
            0x0000681c => Some(Self::Sp),
            0x0000681e => Some(Self::Mepc),
            0x00006816 => Some(Self::Sepc),
            0x00006818 => Some(Self::Mstatus),
            0xff007000 => Some(Self::A0),
            0xff007002 => Some(Self::A1),
            0xff007004 => Some(Self::A2),
            0xff007006 => Some(Self::A3),
            0xff007008 => Some(Self::A4),
            0xff00700a => Some(Self::A5),
            0xff00700c => Some(Self::A6),
            0xff00700e => Some(Self::A7),
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
            Self::Mstatus => {
                context.mstatus = value;
                log::debug!("Setting mstatus to {:x}", context.mstatus);
            }
            Self::Sepc => {
                context.sepc = value;
                log::debug!("Setting sepc to {:x}", context.sepc);
            }
            Self::Mepc => {
                context.mepc = value - 0x4; //This is because before returning
                                            //there's an mepc+4. A flag can be added to
                                            //determine before returning whether to inc by 4 or
                                            //not. This works for now.
                log::debug!("Setting mepc to {:x}", context.mepc);
            }
            Self::A0 => context.reg_state.a0 = value as isize,
            Self::A1 => context.reg_state.a1 = value as isize,
            Self::A2 => context.reg_state.a2 = value,
            Self::A3 => context.reg_state.a3 = value,
            Self::A4 => context.reg_state.a4 = value,
            Self::A5 => context.reg_state.a5 = value,
            Self::A6 => context.reg_state.a6 = value,
            Self::A7 => context.reg_state.a7 = value,
        }
    }

    pub fn get(&self, context: &ContextRiscv) -> usize {
        match *self {
            Self::Medeleg => context.medeleg,
            Self::Satp => context.satp,
            Self::Sp => context.sp,
            Self::Mepc => context.mepc,
            Self::Sepc => context.sepc,
            Self::Mstatus => context.mstatus,
            Self::A0 => context.reg_state.a0 as usize,
            Self::A1 => context.reg_state.a1 as usize,
            Self::A2 => context.reg_state.a2,
            Self::A3 => context.reg_state.a3,
            Self::A4 => context.reg_state.a4,
            Self::A5 => context.reg_state.a5,
            Self::A6 => context.reg_state.a6,
            Self::A7 => context.reg_state.a7,
        }
    }
}
