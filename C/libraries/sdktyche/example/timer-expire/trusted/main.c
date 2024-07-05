#include "sdk_tyche_rt.h"
#include "common.h"
#include "enclave_app.h"
#include "tyche_api.h"
// ———————————————————————————————— Globals ————————————————————————————————— //
config_t* shared = NULL;


// ————————————————————————— HELLO_WORLD Functions —————————————————————————— //

// This function simple hogs the cpu.
void hogs(void)
{
  while(1) {}
}

// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(void)
{
  shared = (config_t*) get_default_shared_buffer();
  hogs();
}
