# 005 - VM exit on selected interrupts

## What

We need discriminate between interrupts that can be handled inside the VM and the ones that should trigger an exit.
Ideally we want a synchronous interrupt (i.e., exceptions) bitmap where if an entry is at 1, the corresponding interrupt requires a VM exit, forcing it to be handled inside the manager domain.

## Why

This has several benefits:
1. It can reduce the complexity (and size) of a domain by automatically delegating some of the exceptions.
2. It enables **safe** sandboxing of privileged code.
3. If handled directly at the hardware level, i.e., within the VMCS, it simplifies the loader and the monitor code.

## How

Intel SDM Vol 3 chapter 25.6.4 seems to describe an exception bitmap: 

```
25.6.3 Exception Bitmap

The exception bitmap is a 32-bit field that contains one bit for each exception. When an exception occurs, its vector is used to select a bit in this field.  
If the bit is 1, the exception causes a VM exit. If the bit is 0, the exception is delivered normally through the IDT, using the descriptor corresponding to the exception’s vector.

Whether a page fault (exception with vector 14) causes a VM exit is determined by bit 14 in the exception bitmap as well as the error code produced by the page fault and two 32-bit fields in the VMCS (the page-fault error-code mask and page-fault error-code match).  
See Section 26.2 for details.
```


The exception bitmap is part of the tertiary processor base VM execution controls.
It is located [here](https://github.com/CharlyCst/vmxvmm/blob/main/crates/vmx/src/lib.rs#L604) in our implementation.

We update the switch operation to setup the exception bitmap according to the domain's configuration.

When an unallowed exception arises in a domain, the monitor finds the manager responsible for handling it and reinjects the fault into the CPU after switching to the manager domain. 

For the moment, we only handle the first 32 interrupts.
Support for other ones will be added once we figure out APIC.



