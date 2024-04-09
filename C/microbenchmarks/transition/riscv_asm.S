#if defined(CONFIG_RISCV) || defined(__riscv)

.text

// Take a capa_index_t* and a void** 
.globl fast_call_gate
fast_call_gate:
    mv a1, a0
    li a0, 0x8  
    li a7, 0x5479636865
    ecall 
    ret 

#endif 
