#ifndef __TRT_INCLUDE_BRICKS_H__
#define __TRT_INCLUDE_BRICKS_H__

#include "sdk_tyche_rt.h"

// extern int bricks_gate_call(frame_t* frame);
// extern int bricks_gate_call();

// ———————————————————————————————— Entry functions in Bricks  ————————————————————————————————— 

extern void bricks_trusted_entry(frame_t* frame);
extern void bricks_trusted_main(capa_index_t ret_handle, void* args);

// ———————————————————————————————— Functions from Bricks (testing) ————————————————————————————————— 

extern int bricks_function(int a, int b);
extern void* bricks_get_default_shared_buffer();

// ———————————————————————————————— Exception/interrupts handlers from Bricks  ————————————————————————————————— 

extern void bricks_exception_handler();
extern void bricks_divide_zero_handler();

// ———————————————————————————————— Syscall handlers from Bricks  ————————————————————————————————— 

extern void bricks_syscall_handler();

#endif