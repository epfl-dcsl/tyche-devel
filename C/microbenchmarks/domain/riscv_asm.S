#if defined(CONFIG_RISCV) || defined(__riscv)

.text

.globl _start
_start:
  mv a2, a3
  .option push 
  .option norelax
  la gp, __global_pointer$ 
  .option pop 
  .option relax
  // Should never return here, call exit if we do.
  li a0, 0x1
  li a7, 0x5479636865
  ecall 

#endif 
