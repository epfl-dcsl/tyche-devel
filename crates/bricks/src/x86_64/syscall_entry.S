.comm USER_RSP, 8, 8
.comm BRICKS_RSP, 8, 8
.comm SAVE_RAX, 8, 8
.comm SAVE_RCX, 8, 8
.comm SAVE_RDI, 8, 8

.globl bricks_syscall_entry
bricks_syscall_entry:
    movq %rsp, USER_RSP 
    movq BRICKS_RSP, %rsp 
    movq %rax, SAVE_RAX
    movq %rcx, SAVE_RCX
    movq %rdi, SAVE_RDI  
    callq bricks_syscall_handler