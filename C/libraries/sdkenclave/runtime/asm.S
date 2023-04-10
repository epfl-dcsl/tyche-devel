.text

.globl _start
_start:
  movq %r11, %rsi
  callq trusted_main
  // Should never return here, call exit if we do.
  movq $1, %rax
  vmcall
