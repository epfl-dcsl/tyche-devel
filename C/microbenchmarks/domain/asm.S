#if defined CONFIG_X86  || defined(__x86_64__)

.text

.globl _start
_start:
  // Should never return here, call exit if we do.
  movq $1, %rax
  vmcall

#endif 
