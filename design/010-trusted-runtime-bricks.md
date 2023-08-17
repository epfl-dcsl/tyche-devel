# 009 - Trusted runtime - Bricks

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