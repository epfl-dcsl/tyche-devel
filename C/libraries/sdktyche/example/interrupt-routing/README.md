#define Vector(n) \
.global vector_##n;       \
vector_##n:               \
    movq 0(%rsp), %rdi;    \
    movq 8(%rsp), %rsi;    \
    movq 16(%rsp), %rdx; \
    movq 24(%rsp), %rcx; \
    movq $10, %rax; \
    vmcall; \
    pushq %rax;           \
    pushq %rdi;           \
    pushq %rcx;           \
    pushq %rdx;           \
    movq $0x10, %rax;      \
    mov %eax, %ds;         \
    mov %eax, %es;         \
    movq $n, %rdi;         \
    movq $10, %rax;        \
    vmcall;                 \
    movq $0, %rax;          \
    movq $0, %rdx;          \
    movq $0x80B, %rcx;      \
    wrmsr;                  \
    popq %rdx;              \
    popq %rcx;              \
    popq %rdi;              \
    popq %rax;              \
    iretq
    
    
    interrupt_handler_stub:
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rsp
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq $0x10, %rax
    mov %eax, %ds             # Load kernel data segment
    mov %eax, %es
    call interrupt_handler_c   # Call the C handler
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rsp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
    addq $8, %rsp              # Remove the pushed vector
    iretq                      # Return from interrupt
