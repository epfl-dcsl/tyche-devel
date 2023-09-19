#include "tyche_api.h"
#include "common.h"

/// Simple generic vmcall implementation.
int tyche_call(vmcall_frame_t* frame)
{
  usize result = FAILURE;
    //DEBUG("frame va: %p", frame);
#if defined(CONFIG_X86) || defined(__x86_64__)
  asm volatile(
    // Setting arguments.
    "movq %7, %%rax\n\t"
    "movq %8, %%rdi\n\t"
    "movq %9, %%rsi\n\n"
    "movq %10, %%rdx\n\t"
    "movq %11, %%rcx\n\t"
    "movq %12, %%r8\n\t"
    "movq %13, %%r9\n\t"
    "vmcall\n\t"
    // Receiving results.
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    "movq %%rsi, %2\n\t"
    "movq %%rdx, %3\n\t"
    "movq %%rcx, %4\n\t"
    "movq %%r8,  %5\n\t"
    "movq %%r9,  %6\n\t"
    : "=rm" (result), "=rm" (frame->value_1), "=rm" (frame->value_2), "=rm" (frame->value_3), "=rm" (frame->value_4), "=rm" (frame->value_5), "=rm" (frame->value_6)
    : "rm" (frame->vmcall), "rm" (frame->arg_1), "rm" (frame->arg_2), "rm" (frame->arg_3), "rm" (frame->arg_4), "rm" (frame->arg_5), "rm" (frame->arg_6) 
    : "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory");
#elif defined(CONFIG_RISCV) || defined(__riscv)
  //TODO(neelu)
  //TEST(0);
    asm volatile(
        //"mv t0, a0\n\t"
        "addi sp, sp, -9*8\n\t"
        "sd a0, 0*8(sp)\n\t"
        "sd a1, 1*8(sp)\n\t"
        "sd a2, 2*8(sp)\n\t"
        "sd a3, 3*8(sp)\n\t"
        "sd a4, 4*8(sp)\n\t"
        "sd a5, 5*8(sp)\n\t"
        "sd a6, 6*8(sp)\n\t"
        "sd a7, 7*8(sp)\n\t"
        "mv a0, %[sa0]\n\t"
        "mv a1, %[sa1]\n\t"
        "mv a2, %[sa2]\n\t"
        "mv a3, %[sa3]\n\t"
        "mv a4, %[sa4]\n\t"
        "mv a5, %[sa5]\n\t" 
        "mv a6, %[sa6]\n\t"
        //"mv a0, %[sa0]\n\t"
        //"mv a7, %[sa7]\n\t"
	    "li a7, 0x78ac5b\n\t"
        //"ld t0, 0x1(x0)\n\t"
        "ecall\n\t"
        //"wfi"	//TODO: Update this to be usable by both U-mode and S-mode.
        //"csrs sstatus, %[mask]\n\t"
        "mv %[da0], a0\n\t"
        "mv %[da1], a1\n\t"
        "mv %[da2], a2\n\t"
        "mv %[da3], a3\n\t"
        "mv %[da4], a4\n\t" 
        "mv %[da5], a5\n\t"
        "mv %[da6], a6\n\t"
        "ld a0, 0*8(sp)\n\t"
        "ld a1, 1*8(sp)\n\t"
        "ld a2, 2*8(sp)\n\t"
        "ld a3, 3*8(sp)\n\t"
        "ld a4, 4*8(sp)\n\t"
        "ld a5, 5*8(sp)\n\t"
        "ld a6, 6*8(sp)\n\t"
        "ld a7, 7*8(sp)\n\t"
        "addi sp, sp, 9*8\n\t"

        //"mv a0, t0\n\t"
        : [da0]"=r" (result), [da1]"=r" (frame->value_1), [da2]"=r" (frame->value_2), [da3]"=r" (frame->value_3), [da4]"=r" (frame->value_4), [da5]"=r" (frame->value_5), [da6]"=r" (frame->value_6)
        :  [sa0]"r" (frame->vmcall), [sa1]"r" (frame->arg_1), [sa2]"r" (frame->arg_2), [sa3]"r" (frame->arg_3), [sa4]"r" (frame->arg_4), [sa5]"r" (frame->arg_5), [sa6]"r" (frame->arg_6)   
           //, [sa7]"r" (frame->arg_7)
           //, [mask]"r" (1 << 18)
	    : "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"
    );
#endif
  return (int)result;
} 

/// Simple generic vmcall implementation with cli.
int tyche_call_cli(vmcall_frame_t* frame)
{
  usize result = FAILURE;
#if defined(CONFIG_X86) || defined(__x86_64__)
  asm volatile(
    // Setting arguments.
    "movq %7, %%rax\n\t"
    "movq %8, %%rdi\n\t"
    "movq %9, %%rsi\n\n"
    "movq %10, %%rdx\n\t"
    "movq %11, %%rcx\n\t"
    "movq %12, %%r8\n\t"
    "movq %13, %%r9\n\t"
    "cli\n\t"
    "vmcall\n\t"
    // Receiving results.
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    "movq %%rsi, %2\n\t"
    "movq %%rdx, %3\n\t"
    "movq %%rcx, %4\n\t"
    "movq %%r8,  %5\n\t"
    "movq %%r9,  %6\n\t"
    "sti\n\t"
    : "=rm" (result), "=rm" (frame->value_1), "=rm" (frame->value_2), "=rm" (frame->value_3), "=rm" (frame->value_4), "=rm" (frame->value_5), "=rm" (frame->value_6)
    : "rm" (frame->vmcall), "rm" (frame->arg_1), "rm" (frame->arg_2), "rm" (frame->arg_3), "rm" (frame->arg_4), "rm" (frame->arg_5), "rm" (frame->arg_6) 
    : "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "memory");
#elif defined(CONFIG_RISCV) || defined(__riscv)
  //TODO(neelu)
  //TEST(0);
  asm volatile(
        //"mv t0, a0\n\t"
        "addi sp, sp, -9*8\n\t"
        "sd a0, 0*8(sp)\n\t"
        "sd a1, 1*8(sp)\n\t"
        "sd a2, 2*8(sp)\n\t"
        "sd a3, 3*8(sp)\n\t"
        "sd a4, 4*8(sp)\n\t"
        "sd a5, 5*8(sp)\n\t"
        "sd a6, 6*8(sp)\n\t"
        "sd a7, 7*8(sp)\n\t"
        "mv a0, %[sa0]\n\t"
        "mv a1, %[sa1]\n\t"
        "mv a2, %[sa2]\n\t"
        "mv a3, %[sa3]\n\t"
        "mv a4, %[sa4]\n\t"
        "mv a5, %[sa5]\n\t" 
        "mv a6, %[sa6]\n\t"
        //"mv a0, %[sa0]\n\t"
        //"mv a7, %[sa7]\n\t"
	    "li a7, 0x78ac5b\n\t"
        //"ld t0, 0x1(x0)\n\t"
        "ecall\n\t"
        //"wfi"	//TODO: Update this to be usable by both U-mode and S-mode.
        //"csrs sstatus, %[mask]\n\t"
        "mv %[da0], a0\n\t"
        "mv %[da1], a1\n\t"
        "mv %[da2], a2\n\t"
        "mv %[da3], a3\n\t"
        "mv %[da4], a4\n\t" 
        "mv %[da5], a5\n\t"
        "mv %[da6], a6\n\t"
        "ld a0, 0*8(sp)\n\t"
        "ld a1, 1*8(sp)\n\t"
        "ld a2, 2*8(sp)\n\t"
        "ld a3, 3*8(sp)\n\t"
        "ld a4, 4*8(sp)\n\t"
        "ld a5, 5*8(sp)\n\t"
        "ld a6, 6*8(sp)\n\t"
        "ld a7, 7*8(sp)\n\t"
        "addi sp, sp, 9*8\n\t"

        //"mv a0, t0\n\t"
        : [da0]"=r" (result), [da1]"=r" (frame->value_1), [da2]"=r" (frame->value_2), [da3]"=r" (frame->value_3), [da4]"=r" (frame->value_4), [da5]"=r" (frame->value_5), [da6]"=r" (frame->value_6)
        :  [sa0]"r" (frame->vmcall), [sa1]"r" (frame->arg_1), [sa2]"r" (frame->arg_2), [sa3]"r" (frame->arg_3), [sa4]"r" (frame->arg_4), [sa5]"r" (frame->arg_5), [sa6]"r" (frame->arg_6)   
           //, [sa7]"r" (frame->arg_7)
           //, [mask]"r" (1 << 18)
	    : "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"
    );

#endif
  return (int)result;
} 

int tyche_create_domain(capa_index_t* management) {
  vmcall_frame_t frame;
  if (management == NULL) {
    goto fail;
  }
  frame.vmcall = TYCHE_CREATE_DOMAIN;
  if (tyche_call(&frame) != SUCCESS) {
    goto fail;
  }
  *management = frame.value_1;
  return SUCCESS;
fail:
  return FAILURE;
}

int tyche_set_traps(capa_index_t management, usize traps)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_CONFIGURE,
    .arg_1 = TYCHE_CONFIG_TRAPS,
    .arg_2 = management,
    .arg_3 = traps,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_set_cores(capa_index_t management, usize cores)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_CONFIGURE,
    .arg_1 = TYCHE_CONFIG_CORES,
    .arg_2 = management,
    .arg_3 = cores,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_set_perm(capa_index_t management, usize perm)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_CONFIGURE,
    .arg_1 = TYCHE_CONFIG_PERMISSIONS,
    .arg_2 = management,
    .arg_3 = perm,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_set_switch(capa_index_t management, usize swtype)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_CONFIGURE,
    .arg_1 = TYCHE_CONFIG_SWITCH,
    .arg_2 = management,
    .arg_3 = swtype,
  };
  if (tyche_call_cli(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_set_entry(
    capa_index_t management,
    usize core,
    usize cr3,
    usize rip,
    usize rsp)
{

  vmcall_frame_t frame = {
    .vmcall = TYCHE_SET_ENTRY_ON_CORE,
    .arg_1 = management,
    .arg_2 = core,
    .arg_3 = cr3,
    .arg_4 = rip,
    .arg_5 = rsp,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_seal(capa_index_t* transition, capa_index_t management)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SEAL_DOMAIN,
    .arg_1 = management,
  };
  if (transition == NULL) {
    goto failure;
  }

  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  *transition = frame.value_1;
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_segment_region(
    capa_index_t capa,
    capa_index_t* left,
    capa_index_t* right,
    usize start1,
    usize end1,
    usize prot1,
    usize start2,
    usize end2,
    usize prot2)
{

  //printk("%s capa %llu, st1: %llu, end1: %llu, st2: %llu, end2: %llu\n",__func__, capa, ); 

  vmcall_frame_t frame = {
    TYCHE_SEGMENT_REGION,
    capa,
    start1,
    end1,
    start2,
    end2,
    (prot1 << 32 | prot2),
  };
  if (left == NULL || right == NULL) {
    goto failure;
  }

  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  } 
  *left = frame.value_1;
  *right = frame.value_2;
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_send(capa_index_t dest, capa_index_t capa) {
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SEND,
    .arg_1 = capa,
    .arg_2 = dest,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  // Check that the revocation handle is the original one.
  if (frame.value_1 != capa) {
    goto failure;
  }
  return SUCCESS;
failure:
  return FAILURE;
}

// TODO: do not exist anymore in v3!
int tyche_share(
    capa_index_t* left,
    capa_index_t dest,
    capa_index_t capa,
    usize a1,
    usize a2,
    usize a3)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SHARE,
    .arg_1 = dest,
    .arg_2 = capa,
    .arg_3 = a1,
    .arg_4 = a2,
    .arg_5 = a3
  };
  if (left == NULL || tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  *left = frame.value_1; 
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_duplicate(capa_index_t* new_capa, capa_index_t capa) {
  vmcall_frame_t frame = {
   .vmcall = TYCHE_DUPLICATE, 
  };
  if (new_capa == NULL || tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  *new_capa = frame.arg_1;

  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_revoke(capa_index_t id)
{
  vmcall_frame_t frame = {
    .vmcall = TYCHE_REVOKE,
    .arg_1 = id,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  //ERROR("Neelu: Tyche_call successful");
  return SUCCESS;
failure:
  return FAILURE;
}

int tyche_switch(capa_index_t* transition_handle, void* args)
{
  usize result = FAILURE;
  vmcall_frame_t frame = {
    .vmcall = TYCHE_SWITCH,
    .arg_1 = 0,
    .arg_3 = (usize) args, // TODO: not yet handled by v3
  };
  if (transition_handle == NULL) {
    ERROR("Received null handle");
    return FAILURE;
  }
  frame.arg_1 = *transition_handle;
  //DEBUG("About to switch from the capability lib: handle %lld", transition_handle);

#if defined(CONFIG_X86) || defined(__x86_64__)
  // TODO We must save some registers on the stack.
  asm volatile(
    // Saving registers.
    "pushq %%rbp\n\t"
    "pushq %%rbx\n\t"
    "pushq %%rcx\n\t"
    "pushq %%rdx\n\t"
    "pushq %%r10\n\t"
    "pushq %%r11\n\t"
    "pushq %%r12\n\t"
    "pushq %%r13\n\t"
    "pushq %%r14\n\t"
    "pushq %%r15\n\t"
    "pushfq\n\t"
    "cli \n\t"
    "movq %2, %%rax\n\t"
    "movq %3, %%rdi\n\t"
    "movq %4, %%rsi\n\t"
    "movq %5, %%r11\n\t"
    "vmcall\n\t"
    // Restoring registers first, otherwise gcc uses them.
    "popfq\n\t"
    "popq %%r15\n\t"
    "popq %%r14\n\t"
    "popq %%r13\n\t"
    "popq %%r12\n\t"
    "popq %%r11\n\t"
    "popq %%r10\n\t"
    "popq %%rdx\n\t"
    "popq %%rcx\n\t"
    "popq %%rbx\n\t"
    "popq %%rbp\n\t"
    // Get the result from the call.
    "movq %%rax, %0\n\t"
    "movq %%rdi, %1\n\t"
    : "=rm" (result), "=rm" (frame.value_1)
    : "rm" (frame.vmcall), "rm" (frame.arg_1), "rm" (frame.arg_2), "rm" (frame.arg_3)
    : "rax", "rdi", "rsi", "r11", "memory");

  // Set the return handle as the one used to do the switch got consummed.
  *transition_handle = frame.value_1;
#elif defined(CONFIG_RISCV) || defined(__riscv)
  //TODO(neelu)
  asm volatile(
        "addi sp, sp, -6*8\n\t"
        "sd a0, 0*8(sp)\n\t"
        "sd a1, 1*8(sp)\n\t"
        "sd a2, 2*8(sp)\n\t"
        "sd a3, 3*8(sp)\n\t"
        "sd a7, 4*8(sp)\n\t"
        "mv a0, %[sa0]\n\t"
        "mv a1, %[sa1]\n\t"
        "mv a2, %[sa2]\n\t"
        "mv a3, %[sa3]\n\t"
	    //"wfi"	//TODO: Update this to be usable by both U-mode and S-mode. 
        "li a7, 0x78ac5b\n\t"
        "ecall\n\t"
        //"ld t0, 0x1(x0)\n\t"
        "mv %[da0], a0\n\t"
        "mv %[da1], a1\n\t"
        "ld a0, 0*8(sp)\n\t"
        "ld a1, 1*8(sp)\n\t"
        "ld a2, 2*8(sp)\n\t"
        "ld a3, 3*8(sp)\n\t"
        "ld a7, 4*8(sp)\n\t"
        "addi sp, sp, 6*8\n\t"
        : [da0]"=r" (result), [da1]"=r" (frame.value_1) 
        : [sa0]"r" (frame.vmcall), [sa1]"r" (frame.arg_1), [sa2]"r" (frame.arg_2), [sa3]"r" (frame.arg_3)
        : "a0", "a1", "a2", "a3", "a7"
	);
   *transition_handle = frame.value_1;
#endif
  return result;
}


int tyche_domain_attestation(usize nonce, unsigned long long* ans, int mode) {
  vmcall_frame_t frame = {
    .vmcall = TYCHE_ENCLAVE_ATTESTATION,
    .arg_1 = nonce,
    .arg_2 = mode,
  };
  if (tyche_call(&frame) != SUCCESS) {
    goto failure;
  }
  
  ans[0] = frame.value_1;
  ans[1] = frame.value_2;
  ans[2] = frame.value_3;
  ans[3] = frame.value_4;
  ans[4] = frame.value_5;
  ans[5] = frame.value_6;
  
  return SUCCESS;
failure:
  return FAILURE;
}
