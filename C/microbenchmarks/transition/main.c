extern void fast_call_gate(unsigned long long t);

void trusted_entry(void)
{
	while(1) {
		fast_call_gate(0xdeadbeef);
	} 
}
