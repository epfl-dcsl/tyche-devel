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
- Profiles - deciding behaviour in compile-time using custom flags
    - System calls profiles
    - Interrupts profiles
    - Exceptions profiles

## TODO

- Memory management
- Fixing interrupts globally, not just trt related

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