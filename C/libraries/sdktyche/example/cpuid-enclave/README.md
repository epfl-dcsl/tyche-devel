# Simple enclave performing CPUID 


## How to run

This application runs by default or if you type:

```
./cpuid_enclave
```

### What it does

The application loads and enclave that runs `cpuid` in a loop.
This will only work with the sdk-kvm backend and is mainly used to debug the performance/behavior
of our emulation stack for CPUID.
