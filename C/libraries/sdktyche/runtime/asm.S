#if defined CONFIG_X86  || defined(__x86_64__)

.text

// Take a capa_index_t* and a void**, expected to be in rdi, rsi.
.globl asm_call_gate
asm_call_gate:
    pushq %rbp
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushfq
    // Now do the call, arguments are in the right registers.
    //pushq %rdi
    //pushq %rsi
    //movq (%rdi), %rdi
    //movq (%rsi), %rsi
    movq $9, %rax   // TYCHE_SWITCH 
    vmcall
    // We returned, move the return values into the registers.
    //popq %r15 // &rsi, i.e., void**
    //movq %rsi, (%r15)
    //popq %r15 // &rdi, i.e., capa_index_t* 
    //movq %rdi, (%r15)
    // Restore all registers, don't change rax.
    popfq
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rbp
    ret


.globl _start
_start:
  //movq %r11, %rsi
  callq trusted_main
  // Should never return here, call exit if we do.
  movq $1, %rax
  vmcall

#endif 
