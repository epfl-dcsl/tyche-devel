use riscv_utils::RegisterState;

#[derive(Debug)]
pub struct ContextRiscv {
    pub reg_state: RegisterState,
    pub satp: usize,
    pub mepc: usize,
    pub sepc: usize,
    pub sp: usize,
    pub medeleg: usize,
    pub mstatus: usize,
}
