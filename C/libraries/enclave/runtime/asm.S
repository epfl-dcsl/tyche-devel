.text

.globl encl_start
encl_start:
  movq %r11, %rsi
  callq trusted_entry
  // Should never return here, call exit if we do.
  movq $1, %rax
  vmcall
