# 002 - Removing Contexts

## What?

The capability engine has a notion of "context", which represents an execution context for a given domain (e.g. registers such as program counter).
When a domain is scheduled on a core, it is scheduled with a given context.
I propose to remove the notion of context, and instead to have an implicit per-core context for each domain.

## Why?

The contexts were originally introduced to make the programming model easier: it is possible to do calls into the domain, return and then resume the call.
This programming model looks a lot like SGX for instance, where contexts are TCS (thread control structures).
Contexts works well with switches (calls into a domain), but they are not well suited for handling interrupts and exceptions.
Indeed, we need to select a context when a domain must be scheduled to handle an interrupt or because a domain it manages was killed.

Unfortunately, creating a new context can fail due to OOM, which prevents the manager domain to be scheduled on the core, putting the system in state where a panic is the only sensible solution.
A solution to this shortcoming would be to pre-allocate contexts for exception handling.
But as context can be kept alive indefinitely, we still need to allocate a fresh context for the next exception and thus delaying the problem without solving it.

Another more philosophical issue I have with context is that they are a "high level" construct, basically threads, which feels odd to implement into the isolation monitor.
Having a single "core" abstraction, with one context per core, would feel more in line with the rest of the isolation monitor design, as a monitor exposing the hardware directly.

## How?

I propose to remove the context abstraction entirely from the capability engine.
The monitor itself will still keep a per-core and per-domain context.

There are two mains implications: for context switches, and for interrupts.

- Context switches become a bit more complicated, as the thread abstraction (if desired) must be implemented in the domains.
  Fortunately, this will not change much for our existing enclave application, as they rely on a single context.
  The user-level thread can be implemented by having a small trampoline as the entry point, that then switches the stack, PC and base registers to match the expected context.
- Exceptions becomes much simpler to implement: they match the hardware
  exception model.
  A domain would have an exception handler, basically a PC, and a `iret` mechanism to switch back to the domain that caused the exception if any.
  
  The remaining question with this approach is how to re-inject interrupts in Linux?
  We can have the exception handler in the Tyche driver, but things such as e.g. interrupt timer must be forwarded to Linux.

