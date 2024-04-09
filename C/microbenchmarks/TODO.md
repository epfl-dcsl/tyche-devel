# Tyche microbenchmarks

This folder contains microbenchmarks for tyche:

1. Creation
	* How much time does it take to create a simple domain?
	* What is the difference between creating an enclave and a sandbox? (hashing)
	* We should vary the size I guess to get a plot? (use tychools for that?)
2. Destruction
	* How much times does it take to destroy a domain?
	* What is the difference between an enclave and a sandbox? (zero out)
	* We should vary the size I guess? (use tyche for that?)
3. Transition
	* Measure the cost of transition with both backends (will show use the difference between kvm and other).
	* Measure the cost of transition with a direct vmcall if allowed in user mode.
4. Attestation
	* Function of size?
