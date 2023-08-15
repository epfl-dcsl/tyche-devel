#ifndef __TRT_INCLUDE_BRICKS_H__
#define __TRT_INCLUDE_BRICKS_H__

#include "sdk_tyche_rt.h"

extern int bricks_gate_call(frame_t* frame);
extern int bricks_function(int a, int b);
extern bricks_asm_call_gate(capa_index_t* capa, void** args);
extern void* bricks_get_default_shared_buffer();

#endif