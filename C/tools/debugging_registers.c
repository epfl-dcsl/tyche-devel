
int main(void) {
  asm volatile(
    "movq $10, %%rax\n\t"
    "vmcall\n\t"
    :
    :
    : "rax");
  return 0;
}
