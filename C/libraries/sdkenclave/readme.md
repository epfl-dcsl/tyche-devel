# SDK ENCLAVE

This is the version 2 of the loader that relies on the `tyche` driver.
The loader parses the enclave binary and generates the corresponding page tables.
It then performs an `mmap` call to the driver to allocate the necessary physical memory.
The enclave layout in physical memory is as follows:

````
| ---------- segment 1 ---------- |
| ---------- segment 2 ---------- |
...
| ------------ cr3 -------------- |
| ---------- page entry---------- |
...

````

## Building applications

We are trying to automate as much as possible.
The `runtime` folder contains a definition for the enclave stack and a default shared buffer.
Any section whose name starts with `.tyche_shared` will be mapped by the loader as shared memory. 

The library expects the enclave to define an entry point:

````
extern void trusted_entry(frame_t* frame); 
````

The library further overwrites the `_start` function as we do not expect (for the moment) any libc.
