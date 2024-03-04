#include "tyche_api.h"
#include "sdk_tyche_rt.h"
#include "ecs.h"
// ———————————————————————————— Enclave sections ———————————————————————————— //


/// This is introduced by tychools.
char *shared_buffer = (char*) 0x300000; 

// ————————————————————————————————— Hooks —————————————————————————————————— //
/// Entry point defined by the application.
extern void trusted_entry(void); 

// ——————————————————————————————— Functions ———————————————————————————————— //

capa_index_t find_switch(void) {
  capa_index_t next = 0;
  do {
    capability_t tmp_capa;
    if (enumerate_capa(next, &next, &tmp_capa) != SUCCESS || next == 0) {
      goto failure;
    }
    /// We found it.
    if (tmp_capa.capa_type == Switch) {
      return tmp_capa.local_id;
    }
  } while (next != 0);
failure:
  // Something went wrong.
  int *pewpew = (int*) 0xdeadbabe;
  *pewpew = 0x666;
}

void trusted_main(void)
{
  capa_index_t ret_handle = 0;
  // Call the domain's main.
  trusted_entry(); 

  // Done executing the domain, return.
  gate_call();
  // Should never return, if we do, an exit call happens.
}

extern int asm_call_gate(capa_index_t ret_handle);

//TODO update this.
int gate_call(void)
{
  usize result = FAILURE;
  capa_index_t ret_handle = find_switch();
  
  result = asm_call_gate(ret_handle);

  return result;
}

void* get_default_shared_buffer()
{
  return (void*) (shared_buffer);
}
