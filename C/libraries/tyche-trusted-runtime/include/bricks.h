#ifndef __TRT_INCLUDE_BRICKS_H__
#define __TRT_INCLUDE_BRICKS_H__

typedef unsigned long long capa_index_t;
// ———————————————————————————————— Entry functions in Bricks  ————————————————————————————————— 
extern void bricks_trusted_main(capa_index_t ret_handle, void* args);

// ———————————————————————————————— Functions from Bricks (testing) ————————————————————————————————— 
extern int bricks_function(int a, int b);

#endif