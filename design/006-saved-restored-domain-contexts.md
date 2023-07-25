# 006 - Saved and restored domain contexts

## What

Domains can run anything from an enclave to a full virtual machine.
The set of initial values for their registers and the set of saved/restored ones can therefore vary.
This design document provides three types of initialization/save/restore:

### Shared registers:

The two domains share most of the registers except the program counter, the stack pointer, and the page table root.
This allows fast transitions between domains.

### Copy registers:

The newly created domain gets a copy of the parent's register file and sets its own program counter, stack pointer, and page table root.
This allows fast boostrap of domains that need to run in a domain that is mostly identical to the parent one (e.g., 64 bit mode).

### Fresh set of registers:

The newly created domain gets a fresh register file as if running directly on top of the hardware.

## Why

Introducing these three types of initialization and save/restore of registers allows to optimize for different use cases.
The shared register file allows fast initialization and transitions.
It allows to leverage hardware extensions such as `vmfunc` on x86, avoids cache trashing/micro-architectural flushes.

The second option allows more control of the child domain over descriptor tables without affecting the parent while still benefitting from a fast initialization.
It increases the isolation between the two domains by preventing mistakenly spilling register content from the parent to the child.

The third option is good for full VMs. It provides a fresh environment (a virtual machine) that can be configured independently of the parent domain.
Its intialization takes however more time.

## How

### x86

On x86 the three models are implemented as follows:

1. Shared register: the two domains share the same vcpu. Upon a switch, the monitor replaces the three registers `rip`, `rsp`, `cr3`.
2. Copy register: each domain has its own vcpu. The child domain, upon creation, receives a copy of the parent one and sets `rip`, `rsp`, `cr3`.
3. Fresh register: the child domain receives a fresh VCPU with basic initilization, similar to what we provide the default domain with.

### Plan for RISC-V

On RISC-V, the same can be achieved with a bitmap of registers that need to be overwritten upon a switch.
The monitor will need to maintain a register file per-domain.
