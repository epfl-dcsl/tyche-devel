# SDK Tyche 

The sdk allows to easily build domains (enclaves, sandboxes, or mixes of both).
It is divided into two folders:
1. `loader`: contains the logic to load a domain.
2. `runtime`: small runtime API for the loaded domain.

## Loader

The loader expects a tychools-instrumented binary, i.e., static, with tyche-os-specific segment types that should include the stack and page tables.

The domain binary is expected to be embedded as a section inside the application's binary.

## Runtime

By default, it casts a shared_buffer pointer to the address `0x300000` which should map the enclave's instrumentation done by tychools (make sure you add a shared segment at that address). 


## Examples

The `example` folder contains code for a simple enclave, a simple sandbox, and an application selector that runs various benchmarks inside an enclave.
