# Enclave Example

This folder contains an example of enclave created with the `sdktyche` library.

The external code (and loader) code is in `untrusted`.  
The enclave code is in `trusted`.

This application parses the environment for an `APP` variable to select what should run inside and outside of the enclave.

The available applications are:

1. Transition Benchmark
2. Hello world
3. Malicious
4. Breakpoint

We detail each application below.

## Transition Benchmark

### How to run

```
APP=TRANSITION_BENCHMARK ./app_selector
```

### What it does

The application loads the enclave and performs multiple transitions while measuring the execution time.

### Sample output

```
dev@tyche:/tyche/programs$ APP=TRANSITION_BENCHMARK ./app_selector
[LOG @../../..//sdktyche/loader/lib.c:269 parse_domain] Parsed tychools binary
[LOG @untrusted/main.c:286 main] The binary TRANSITION_BENCHMARK has been loaded!
[LOG @untrusted/main.c:296 main] Calling the application 'TRANSITION_BENCHMARK', good luck!
[LOG @untrusted/main.c:143 transition_benchmark] Executing TRANSITION_BENCHMARK enclave

[LOG @untrusted/main.c:162 transition_benchmark] Run 0: 1000 call-return in 0.034632 seconds
[LOG @untrusted/main.c:162 transition_benchmark] Run 1: 1000 call-return in 0.032926 seconds
[LOG @untrusted/main.c:162 transition_benchmark] Run 2: 1000 call-return in 0.032051 seconds
[LOG @untrusted/main.c:162 transition_benchmark] Run 3: 1000 call-return in 0.030879 seconds
[LOG @untrusted/main.c:162 transition_benchmark] Run 4: 1000 call-return in 0.035238 seconds
[LOG @untrusted/main.c:162 transition_benchmark] Run 5: 1000 call-return in 0.035763 seconds
[LOG @untrusted/main.c:162 transition_benchmark] Run 6: 1000 call-return in 0.032658 seconds
[LOG @untrusted/main.c:162 transition_benchmark] Run 7: 1000 call-return in 0.034575 seconds
[LOG @untrusted/main.c:162 transition_benchmark] Run 8: 1000 call-return in 0.032720 seconds
[LOG @untrusted/main.c:162 transition_benchmark] Run 9: 1000 call-return in 0.034795 seconds
[LOG @untrusted/main.c:169 transition_benchmark] All done!
[LOG @untrusted/main.c:301 main] Done, have a good day!

```

## Hello World

### How to run

This application runs by default or if you type:

```
APP=HELLO_WORLD ./app
```

### What it does

The application loads the enclave and performs two calls to it, printing two different messages.

### Sample output

```
dev@tyche:/tyche/programs$ APP=HELLO_WORLD ./app_selector
[LOG @../../..//sdktyche/loader/lib.c:269 parse_domain] Parsed tychools binary
[LOG @untrusted/main.c:286 main] The binary HELLO_WORLD has been loaded!
[LOG @untrusted/main.c:296 main] Calling the application 'HELLO_WORLD', good luck!
[LOG @untrusted/main.c:110 hello_world] Executing HELLO_WORLD enclave

[LOG @untrusted/main.c:117 hello_world] First enclave message:
Hello World!

[LOG @untrusted/main.c:124 hello_world] Second enclave message:
Bye Bye! :)!

[LOG @untrusted/main.c:131 hello_world] All done!
[LOG @untrusted/main.c:301 main] Done, have a good day!

```

## Malicious

### How to run

```
APP=MALICIOUS ./app
```

### What it does

Similar to hello world, it performs a first call to the enclave and prints the message.
Afterwards, it attempts to read confidential memory.
This should fail, trigger a call to the registered handler.
The handler performs a second call to the enclave to get the second message (proving the enclave is unaffected) and exits.

### Sample output

```
dev@tyche:/tyche/programs$ APP=MALICIOUS ./app_selector
[LOG @../../..//sdktyche/loader/lib.c:269 parse_domain] Parsed tychools binary
[LOG @untrusted/main.c:286 main] The binary MALICIOUS has been loaded!
[LOG @untrusted/main.c:296 main] Calling the application 'MALICIOUS', good luck!
[LOG @untrusted/main.c:186 malicious] Executing MALICIOUS enclave

[LOG @untrusted/main.c:190 malicious] Setting a handler
[LOG @untrusted/main.c:208 malicious] First enclave message:
Hello World!

[LOG @untrusted/main.c:210 malicious] Address we try to read: 7fd912a5e000
[ERROR | tyche::x86_64::guest] EPT Violation! virt: 0x7fd912a5e000, phys: 0x105890000
[INFO | tyche::x86_64::guest] The vcpu VMCS {
    registers {
        rax: 0x7fd912a5e000
        rbx: 0x0
        rcx: 0x7fd91294aa37
        rdx: 0x1
        rip: 0x56246095854f
        rsp: 0x7ffe25077b20
        rbp: 0x7ffe25077bd0
        rsi: 0x1
        rdi: 0x7fd912a51a70
        r8:  0x7fd912a51a70
        r9:  0x7ffe250779ec
        r10: 0x0
        r11: 0x246
        r12: 0x7ffe25077d18
        r13: 0x562460958807
        r14: 0x0
        r15: 0x7fd912aa7040
        cr0: 0x80050033
        cr3: 0x11426b802
        cr4: 0x372ef0
        cs.sel: 0x33
        cs.base: 0x0
        cs.limit: 0xffffffff
        cs.ar: 0xa0fb
        ds.sel: 0x0
        ds.base: 0x0
        ds.limit: 0xffffffff
        ds.ar: 0x1c000
        es.sel: 0x0
        es.base: 0x0
        es.limit: 0xffffffff
        es.ar: 0x1c000
        fs.sel: 0x0
        fs.base: 0x7fd912833740
        fs.limit: 0xffffffff
        fs.ar: 0x1c000
        gs.sel: 0x0
        gs.base: 0x0
        gs.limit: 0xffffffff
        gs.ar: 0x1c000
        ss.sel: 0x2b
        ss.base: 0x0
        ss.limit: 0xffffffff
        ss.ar: 0xc0f3
        ldt.sel: 0x0
        ldt.base: 0x0
        ldt.limit: 0xffffffff
        ldt.ar: 0x1c000
        tr.sel: 0x40
        tr.base: 0xfffffe59c300b000
        tr.limit: 0x4087
        tr.ar: 0x8b
        idt.base: 0xfffffe0000000000
        idt.limit: 0xfff
        gdt.base: 0xfffffe59c3009000
        gdt.limit: 0x7f
        cr0 read shadow: 0x0
        cr0 mask: 0x0
        cr4 read shadow: 0xa0
        cr4 mask: 0x2000
        ia32_efer: 0xd01
        VM Entry Controls: Some(IA32E_MODE_GUEST | LOAD_IA32_EFER)
        VM Exit Controls: Some(HOST_ADDRESS_SPACE_SIZE | SAVE_IA32_EFER | LOAD_IA32_EFER)
        VMCS Pin-Based Controls: Some((empty))
        VMCS PrimaryControls: Some(USE_MSR_BITMAPS | SECONDARY_CONTROLS)
        VMCS SeconaryControls: Some(ENABLE_EPT | ENABLE_RDTSCP | UNRESTRICTED_GUEST | ENABLE_INVPCID | ENABLE_XSAVES_XRSTORS)
        EPT Ptr: 0x15841401e
        EPTP List: 0x0
    }
}

[LOG @untrusted/main.c:46 malicious_handler] Handler called for address 0 and signo 5
[LOG @untrusted/main.c:57 malicious_handler] Recovered. Second message: Bye Bye! :)!

[LOG @untrusted/main.c:64 malicious_handler] It's a success, let's exit.
```

## Breakpoint

### How to run

```
APP=MALICIOUS ./app
```

### What it does

The enclave triggers a breakpoint hardware exception with `int 3`.
The enclave is configured to NOT be allowed to handle its own exception for breakpoint.

What should happen is that it triggers an exit, Tyche should invoke the parent to handle the exception.
Ideally, we would like the exception to be routed all the way to the registered handler in the user application.

For the moment the code does not work exactly as expected and I need to investigate.

### Sample output

For now, we have issues routing it all the way to the application layer.

```
dev@tyche:/tyche/programs$ APP=BREAKPOINT ./app_selector
[LOG @../../..//sdktyche/loader/lib.c:269 parse_domain] Parsed tychools binary
[LOG @untrusted/main.c:286 main] The binary BREAKPOINT has been loaded!
[LOG @untrusted/main.c:296 main] Calling the application 'BREAKPOINT', good luck!
[LOG @untrusted/main.c:227 breakpoint] Executing BREAKPOINT enclave

[LOG @untrusted/main.c:229 breakpoint] Setting a handler for BREAKPOINT
[LOG @untrusted/main.c:239 breakpoint] Calling the enclave now... good luck
[  127.887041] [@/home/aghosn/Documents/Programs/MSR/vmxvmm/C/drivers/tyche/../../libraries/capabilities/src/lib.c:780 switch_domain]
[  127.887059] failed to perform a switch on capa 4222940
[  127.889612] [@/home/aghosn/Documents/Programs/MSR/vmxvmm/C/drivers/tyche/src/domains.c:476 driver_switch_domain]
[  127.889616] Unable to switch to domain 0000000024e2a9e7
[  127.891415] [@/home/aghosn/Documents/Programs/MSR/vmxvmm/C/drivers/tyche/src/ioctl.c:243 tyche_ioctl]
[  127.891417] Unable to switch to domain 0000000024e2a9e7
[ERROR @../../..//sdktyche/loader/driver_ioctl.c:149 ioctl_switch] ioctl failed to switch to 3
[ERROR @../../..//sdktyche/loader/lib.c:464 sdk_call_domain] Unable to switch to the domain 3
[ERROR @untrusted/main.c:242 breakpoint] Unable to call the enclave 3!
[ERROR @untrusted/main.c:298 main] Oups... we received a failure... good luck debugging.

```
