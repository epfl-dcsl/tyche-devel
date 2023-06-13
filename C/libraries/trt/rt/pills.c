


void blue_pill(unsigned long user_rip, unsigned long user_rsp)
{
  asm volatile(
    "movq %0, %%rsp\n\t"
    "pushq %1\n\t"
    "iretq\n\t"
    :
    : "r" (user_rsp), "r" (user_rip));
}
