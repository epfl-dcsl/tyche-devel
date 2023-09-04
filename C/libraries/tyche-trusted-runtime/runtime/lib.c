#include "bricks.h"

// ————————————————————————————————— Hooks —————————————————————————————————— //
/// Entry point defined by the application.
extern void trusted_entry();
// ——————————————————————————————— Functions ———————————————————————————————— //
void trusted_main(capa_index_t ret_handle, void *args)
{
  bricks_trusted_main(ret_handle, args);
}

