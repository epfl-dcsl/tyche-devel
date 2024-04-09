#pragma once

#include "tyche_capabilities_types.h"

// ——————————————————————————————— Constants ———————————————————————————————— //

#define STACK_OFFSET_TOP ((usize)4)

// —————————————————————————————————— API ——————————————————————————————————— //
int gate_call(void);
capa_index_t find_switch(void);
void trusted_main(void);
void* get_default_shared_buffer();
