#if defined CONFIG_X86  || defined(__x86_64__)

.text

.globl fast_call_gate
fast_call_gate:
    movq $8, %rax   // TYCHE_SWITCH 
    vmcall
    ret

#endif 
