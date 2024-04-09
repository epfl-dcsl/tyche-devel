#include "sdk_tyche_rt.h"

extern void fast_call_gate(unsigned long long t);

void trusted_entry(void)
{
	// Hopefully the capa index does not change after the first run.
  unsigned long long capa = find_switch();
	while(1) {
		fast_call_gate(capa);
	} 
}
