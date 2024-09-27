#include "sdk_tyche_rt.h"
#include "common.h"
#include "enclave_app.h"
#include "tyche_api.h"
// ———————————————————————————————— Globals ————————————————————————————————— //
config_t* shared = NULL;

// ————————————————————————————— Entry Function ————————————————————————————— //

void trusted_entry(void)
{
  shared = (config_t*) get_default_shared_buffer();
  while(1) {
    asm volatile(
      "mov $0, %%eax\n\t"
      "cpuid"
      :
      :
      : "eax", "ebx", "ecx");
  }
}
