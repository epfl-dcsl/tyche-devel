# 010 - Trusted runtime - Bricks

## What

This is an overview of how we want our Trusted runtime (Bricks) works. 

## So far

So far our enclaves were running in Ring 0 of our vcpu. Communication with Tyche and untrusted part that loaded the enclave was not that easy and the API was not very clear. 

## Goal

Goal of Bricks is to provide the enclave with support for few things
- communication with untrusted part (gate calls)
- Memory management
- Switching between user and kernel code
- Tyche calls (enclave attestation)

Bricks will have small startup routine to setup interrupts before giving control to user part of the enclave.

## Done

So far, things that were implemented in Bricks
- Setting up IDT and GDT using x86_64 crate
- Setting up system calls using x86_64 crate
- Syscalls
    - PRINT syscall - being able to print text from the enclave. It is implemented as RPC to untrusted part
    - WRITE syscall -  being able to write some number of bytes to shared buffer
    - READ syscall - being able to read some number of bytes from shared buffer
    - ATTEST ENCLAVE - being able to call Tyche to do the attestation, same what we did for the attestation example 
    - GATE CALL - giving up control to untrusted part, can be removed, it has no specific purpose except for debugging
    - MALLOC - requesting memory from the trusted runtime 
    - FREE - returning allocated memory to trusted runtime
- Profiles - deciding behaviour in compile-time using custom flags
    - System calls profiles
    - Interrupts profiles
    - Exceptions profiles

## Memory management

In order to have memory management inside of trusted runtime, page tables need to be mapped inside of the enclave. We need this in order for runtime to change access flags for the memory we want to give to the user and remove user access whet memory is freed. 
This is achieved through using tychools, where the option for mapping can be given in the config file.

We can also give Tychools memory segment that is actually going to represent memory it can access and give to the user. This is done in a same manner in which we give shared buffer memory segment to enclave. 

```
[user part of the enclave]  
             |                  ^
-------------| [malloc call]----|--[return pointer to memory]----                            |        
[Bricks]     v                  ----------------|
|--------|                                      |
| page 1 | <--[take the page]                   |
|--------|   |                                  |
| page 2 |   |             cr3 page tables      |
|--------|   |--------->|-------------------|-->|
                        |change access flags|
                        |                   |

```

## TODO

- Fixing interrupts globally, not just trt related
- Allocation algorithm improvement
- How can we pass arguments to trusted runtime from tychools

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

## Problems

Returning from syscall - possible problem is that it is called from non-user code.
Fixing interrupt from Linux not being properly cleared, it is logic for vcpu, but important to be solved in order for runtime to work.