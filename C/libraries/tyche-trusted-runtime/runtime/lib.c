#include "tyche_api.h"
#include "sdk_tyche_rt.h"
#include "bricks.h"

// ————————————————————————————————— Hooks —————————————————————————————————— //
/// Entry point defined by the application.
extern void trusted_entry(frame_t* frame);
// ——————————————————————————————— Functions ———————————————————————————————— //
void trusted_main(capa_index_t ret_handle, void *args)
{
  bricks_trusted_main(ret_handle, args);
}

