# Skeleton for the redis benchmark 


## How to run

Does not run **yet**.

### What it does

Enventually the goal is to run redis inside an enclave which communicates with a front-encryption enclave.

### Status

We expect the redis-server binary to be available at the path pointed by the `REDIS_SERVER_PATH`.
To generate the enclave, for now, we copy this binary locally and rename it `enclave`.
We then call tychools we default sensible values and that's about it for now.

To do:
1. We need to figure out how to instrument musl and redis to avoid syscalls.
2. We will need to make the binary run inside an enclave.
