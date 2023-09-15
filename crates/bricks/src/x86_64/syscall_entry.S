.globl bricks_syscall_entry
bricks_syscall_entry:

    pushq %rbp
    pushq %rbx
    pushq %rdx
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushfq

    // save user stack and syscall args
    movq %rsp, USER_RSP
    movq %rax, SAVE_RAX
    movq %rcx, SAVE_RCX
    movq %rdi, SAVE_RDI
    movq %rsi, SAVE_RSI

    // user bricks stack
    movq BRICKS_RSP, %rsp

    callq bricks_syscall_handler

    popfq
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %rdx
    popq %rbx
    popq %rbp

    // return from handler
    movq SAVE_RCX, %rcx
    movq USER_RSP, %rsp

    sysret