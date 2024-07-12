#include "sdk_tyche_rt.h"
#include "common.h"
#include "enclave_app.h"
#include "tyche_api.h"

// ————————————————————————— HELLO_WORLD Functions —————————————————————————— //

void noop_loop(void)
{
  config_t* shared  = (config_t*) get_default_shared_buffer();
  shared->flag = MAGIC_VALUE;
  while(1) {}
}

// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(void)
{
  noop_loop();
}
