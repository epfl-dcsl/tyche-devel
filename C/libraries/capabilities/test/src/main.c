#include <stdlib.h>

#include "tyche_capabilities_types.h"
#include "tyche_capabilities.h"

/// Allocator for the capabilities.
void* allocate(unsigned long size)
{
  return malloc(size);
}

/// Deallocator for the capabilities.
void deallocate(void* ptr)
{
  free(ptr);
}


int main(void)
{
  capability_t* curr = NULL;
  /// We init the capability library.
  if (init(allocate, deallocate) != SUCCESS) {
    ERROR("Unable to init the capa library.");
    goto failure;
  }

  /// Did we manage to do the enumeration? 
  dll_foreach(&(local_domain.capabilities), curr, list)
  {
    LOG("A capability %lld", curr->local_id); 
  }
  return 0;
failure:
  return -1;
}
