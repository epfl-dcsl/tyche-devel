#if defined(CONFIG_RISCV) || defined(__riscv)

.text

// Take a capa_index_t* and a void** 
.globl asm_call_gate
asm_call_gate:
    //ld a2, 0x0(a1)      //loading the args - TODO: Make sure this is correct!! Because the tyche call id is supposed to be in a0. 
    //ld a1, 0x0(a0)
    //mv a2, a1 
    //ld a1, 0x0(a1)          //Question: why is ret_handle in a1 and not a0? 
    mv a1, a0
    li a0, 0x9  
    li a7, 0x5479636865
    ecall 
    ret 

.globl _start
_start:
  mv a2, a3
  .option push 
  .option norelax
  la gp, __global_pointer$ 
  .option pop 
  .option relax
  j trusted_main
  // Should never return here, call exit if we do.
  li a0, 0x1
  li a7, 0x5479636865
  ecall 

#endif 
