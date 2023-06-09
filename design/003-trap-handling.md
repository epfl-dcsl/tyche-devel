# 003 - Trap Handling

## What?

Tyche needs a mechanisms to handle traps that occurs in domains, such as interrupts, but also standard exceptions such as page faults or breakpoints.
To handle those, I propose a design close to hardware's exception mechanism with a trap handler and an "iret" monitor call.

## Why?

Handling traps is needed for both long running domains and VMs.
Tyche currently do not support traps: a trap will cause a jump to the kernel trap handler which is most likely not in the domain and will therefore crash the machine (because we can't handle EPT/PMP violation either!).

## How?

The proposed design consists in giving each domain a set of traps it can handle (a 64 bits bitmap in the capa engine, can be interpreted in architecture-specific ways), and keeping a graph of manager domains who are responsible for handling the traps.
Each domain has a manager, when a domain traps it's manager is checked to see if it has the permission to handle the trap, if not the manager's manager is checked, and so on.
The manager has a trap handling context (e.g. a RIP, RSP, and CR3 on x86-64), similar to hardware traps, and can return to the domain that caused the trap using a new `TRET` monitor call.

A new update in the capa engine, the trap update, causes the context switch, while the domain who caused the trap gets recorded for upcoming `TRET`.
This mechanism is different from the domain switch, in particular it does not allocate any switch capability and thus can not fail (which is desirable on the trap path).

Finally, if the domain has no manager that can handle the trap, the machine is shut down like after a triple fault.

