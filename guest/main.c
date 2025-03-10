// Tell the compiler incoming stack alignment is not RSP%16==8 or ESP%16==12

const int RO = 0x888;
int bss;

int rawc_test_function() { return 5; }

__attribute__((force_align_arg_pointer)) void _start() {
  bss = RO;

  asm("movq $0x400A0, %rax;"
      "movq %rax, %cr4;");

  asm("movl $0x7, %eax;"
      "movl $0x0, %edx;"
      "movl $0x0, %ecx;"
      "xsetbv");

  asm("cpuid");

  // Exit
  asm("movl $0xa, %eax;"
      "movl $0xa, %ebx;"
      "vmcall");
  __builtin_unreachable();
}
