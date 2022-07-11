// Tell the compiler incoming stack alignment is not RSP%16==8 or ESP%16==12
__attribute__((force_align_arg_pointer))
void _start()
{
  
  asm("movl $0x666, %eax;"
      "vmcall");
  __builtin_unreachable();
}
