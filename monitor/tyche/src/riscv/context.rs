use riscv_utils::RegisterState;

pub struct ContextRiscv {
    pub reg_state: RegisterState,
    pub satp: usize,
    pub mepc: usize,
    pub sp: usize,
    pub medeleg: usize,
    pub mstatus: usize,
}
