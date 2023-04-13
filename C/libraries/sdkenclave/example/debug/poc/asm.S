.text

.globl make_one 
make_one:
  pushq %rbp
  movq %rsp, %rbp
  movq $1, (%rdi)
  popq %rbp
  ret
