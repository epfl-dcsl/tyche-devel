# 010 - Trusted runtime - Bricks

## What

This is an overview of how we want our Trusted runtime (Bricks) works. 

## Runtime support so far

So far our enclaves were running in Ring 0 of our vcpu. Communication with Tyche and untrusted part that loaded the enclave was not that easy and the API was not very clear. 

## Goal

Goal of Bricks is to provide the enclave with support for few things
- communication with untrusted part (gate calls)
- Memory management
- Switching between user and kernel code
- Tyche calls (enclave attestation)

Bricks will have small startup routine to setup interrupts before giving control to user part of the enclave.

## How is Bricks constructed

Final binary is constructed from two binaries 
- user binary (C code for now to distinguish user/kernel)
- Bricks binary (Rust code)

Binaries are merged into single binary using Tychools. [Example of the config file](../C/libraries/tyche-trusted-runtime/manifests/user_kernel.json) that does this.

Start of the final binary is same as start of the Bricks binary in order to do the setup and then transition into the user mode. 

## Tychools - Bricks

Information from Tychools to Bricks is transfered by adding additional segment right below shared buffer for now. The information written there is used to configure some Bricks features, like
- number of pages reserved for memory pool
- user starting instruction pointer 

## Done

So far, things that were implemented in Bricks (x86)
- Setting up IDT and GDT using x86_64 crate
- Setting up system calls using x86_64 crate
- Syscalls
    - PRINT syscall - being able to print text from the enclave. It is implemented as RPC to untrusted part
    - WRITE syscall -  being able to write some number of bytes to shared buffer (similar to copy to user)
    - READ syscall - being able to read some number of bytes from shared buffer (similar to copy from user)
    - ATTEST ENCLAVE - being able to call Tyche to do the attestation, same what we did for the attestation example 
    - SBRK - standard Linux **sbrk** system call
    - BRK - standard Linux **brk** system call
- Profiles - deciding behaviour in compile-time using custom flags
    - System calls profiles
    - Interrupts profiles
    - Exceptions profiles

## Memory management

In order to have memory management inside of trusted runtime, page tables need to be mapped inside of the enclave. We need this in order for runtime to change access flags for the memory we want to give to the user and remove user access whet memory is freed. 
This is achieved through using tychools, where the option for mapping can be given in the config file.

We can also give Tychools memory segment that is actually going to represent memory it can access and give to the user. This is done in a same manner in which we give shared buffer memory segment to enclave. 

Amount of memory can be configured through Tychools config file by specifying it in Bricks info 

```
"bricks_info" : {
    "memory_pool" : true,
    "memory_pool_size" : 4,
    "user_stack" : true
}
```
Graphical overview of memory management

```
[user part of the enclave]  
             |                  ^
-------------| [sbrk call]----|--[return pointer to memory]----                            |        
[Bricks]     v                  ----------------|
|--------|                                      |
| page 1 | <--[take the page]                   |
|--------|   |                                  |
| page 2 |   |             cr3 page tables      |
|--------|   |--------->|-------------------|-->|
                        |change access flags|
                        |                   |

```
## Graphical overview

```
[user space]                 Enclave user code
                            ^                 |
                            |                 |
----------------------------|-----------------|(system calls and interrupts)---
[kernel space]              |                 |
[start]                     |                 |
------------------------    |            -----v-----------
|Bricks startup routine| ---|            |Bricks handlers | ------> Free pages, shared buffer...
------------------------                  ----------------
                                              |
----------------------------------------------| (calls Tyche if needed)-----------
[ring 0]                                      v
                                Tyche

                                
```

## TODO

- Adding spinlock for static mut variables
- Fixing interrupts globally, not just trt related

## Problems

Returning from syscall - possible problem is that it is called from non-user code.
Fixing interrupt from Linux not being properly cleared, it is logic for vcpu, but important to be solved in order for runtime to work.