# Enclave Example

This folder contains an example of enclave created with the `sdkenclave` library.

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
APP=TRANSITION_BENCHMARK ./app
```

### What it does

The application loads the enclave and performs multiple transitions while measuring the execution time.

### Sample output

```
dev@tyche:/tyche/programs$ APP=TRANSITION_BENCHMARK ./app
[LOG @untrusted/main.c:282 main] Let's load the binary 'enclave'!
[LOG @untrusted/main.c:304 main] Calling the application 'TRANSITION_BENCHMARK', good luck!
[LOG @untrusted/main.c:153 transition_benchmark] Executing TRANSITION_BENCHMARK enclave

[LOG @untrusted/main.c:172 transition_benchmark] Run 0: 1000 call-return in 0.055736 seconds
[LOG @untrusted/main.c:172 transition_benchmark] Run 1: 1000 call-return in 0.052514 seconds
[LOG @untrusted/main.c:172 transition_benchmark] Run 2: 1000 call-return in 0.054366 seconds
[LOG @untrusted/main.c:172 transition_benchmark] Run 3: 1000 call-return in 0.051372 seconds
[LOG @untrusted/main.c:172 transition_benchmark] Run 4: 1000 call-return in 0.050164 seconds
[LOG @untrusted/main.c:172 transition_benchmark] Run 5: 1000 call-return in 0.051758 seconds
[LOG @untrusted/main.c:172 transition_benchmark] Run 6: 1000 call-return in 0.049921 seconds
[LOG @untrusted/main.c:172 transition_benchmark] Run 7: 1000 call-return in 0.051790 seconds
[LOG @untrusted/main.c:172 transition_benchmark] Run 8: 1000 call-return in 0.052617 seconds
[LOG @untrusted/main.c:172 transition_benchmark] Run 9: 1000 call-return in 0.049116 seconds
[LOG @untrusted/main.c:179 transition_benchmark] All done!
[LOG @untrusted/main.c:309 main] Done, have a good day!
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
dev@tyche:/tyche/programs$ APP=HELLO_WORLD ./app
[LOG @untrusted/main.c:282 main] Let's load the binary 'enclave'!
[LOG @untrusted/main.c:304 main] Calling the application 'HELLO_WORLD', good luck!
[LOG @untrusted/main.c:120 hello_world] Executing HELLO_WORLD enclave

[LOG @untrusted/main.c:127 hello_world] First enclave message:
Hello World!

[LOG @untrusted/main.c:134 hello_world] Second enclave message:
Bye Bye! :)!

[LOG @untrusted/main.c:141 hello_world] All done!
[LOG @untrusted/main.c:309 main] Done, have a good day!
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
dev@tyche:/tyche/programs$ APP=MALICIOUS ./app
[LOG @untrusted/main.c:282 main] Let's load the binary 'enclave'!
[LOG @untrusted/main.c:304 main] Calling the application 'MALICIOUS', good luck!
[LOG @untrusted/main.c:196 malicious] Executing MALICIOUS enclave

[LOG @untrusted/main.c:200 malicious] Setting a handler
[LOG @untrusted/main.c:218 malicious] First enclave message:
Hello World!

[LOG @untrusted/main.c:220 malicious] Address we try to read: 7f52824ab000
[ERROR | tyche::x86_64::guest] EPT Violation! virt: 0x7f52824ab000, phys: 0x10f300000
[INFO | tyche::x86_64::guest] The vcpu VMCS {
    registers {
        rax: 0x7f52824ab000
        rbx: 0x0
        rcx: 0x7f5282636a37
        rdx: 0x1
        rip: 0x56415a0401f4
        rsp: 0x7ffcde44e680
        rbp: 0x7ffcde44e730
        rsi: 0x1
        rdi: 0x7f528273da70
        r8:  0x7f528273da70
        r9:  0x7ffcde44e54c
        r10: 0x0
        r11: 0x246
        r12: 0x7ffcde44e868
        r13: 0x56415a0404bf
        r14: 0x0
        r15: 0x7f5282793040
        cr0: 0x80050033
        cr3: 0x105cab803
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
        fs.base: 0x7f528251f740
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
        tr.base: 0xfffffe3a65578000
        tr.limit: 0x4087
        tr.ar: 0x8b
        idt.base: 0xfffffe0000000000
        idt.limit: 0xfff
        gdt.base: 0xfffffe3a65576000
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
        EPT Ptr: 0x1583ad01e
        EPTP List: 0x0
    }
}

[LOG @untrusted/main.c:57 malicious_handler] Handler called for address 0
[LOG @untrusted/main.c:68 malicious_handler] Recovered. Second message: Bye Bye! :)!

[LOG @untrusted/main.c:75 malicious_handler] It's a success, let's exit.
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

For now, the program should get killed by Linux as below:

```
dev@tyche:/tyche/programs$ APP=BREAKPOINT ./app
[LOG @untrusted/main.c:282 main] Let's load the binary 'enclave'!
[LOG @untrusted/main.c:304 main] Calling the application 'BREAKPOINT', good luck!
[LOG @untrusted/main.c:237 breakpoint] Executing BREAKPOINT enclave

[LOG @untrusted/main.c:239 breakpoint] Setting a handler for BREAKPOINT
[LOG @untrusted/main.c:249 breakpoint] Calling the enclave now... good luck
[  496.087534] BUG: unable to handle page fault for address: 000000005e821edd
[  496.091930] #PF: supervisor write access in kernel mode
[  496.095628] #PF: error_code(0x0002) - not-present page
[  496.098604] PGD 0 P4D 0
[  496.100486] Oops: 0002 [#1] PREEMPT SMP PTI
[  496.103816] CPU: 0 PID: 27393 Comm: app Tainted: G           O       6.2.0 #6
[  496.110168] RIP: 0010:tyche_switch+0x3b/0x5d [tyche]
[  496.113113] Code: 00 00 ba 09 00 00 00 45 31 c0 55 53 51 52 41 52 41 53 41 54 41 55 41 56 41 57 9c fa 48 89 d0 48 8b 39 4c 89 c6 4d 89 cb 0f 01 <c1> 9d 41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 5a 59 5b 5d 48 89 c2 49
[  496.124039] RSP: 0018:ffffc9000070be08 EFLAGS: 00010202
[  496.125824] RAX: 000000000040bfdc RBX: ffff88810b87abe0 RCX: ffff88810f1a9d80
[  496.128591] RDX: 00000000004011eb RSI: 0000000000000000 RDI: 000000000040bfdc
[  496.130885] RBP: 000000000040bf9c R08: 0000000000000000 R09: 0000000000000000
[  496.133549] R10: 0000000000000000 R11: 0000000000000000 R12: ffff88811c001800
[  496.137902] R13: 00007ffcc4a7b2a8 R14: ffff88811437de00 R15: 0000000000000000
[  496.138995] FS:  00007f09b860f740(0000) GS:ffff888154600000(0000) knlGS:0000000000000000
[  496.140494] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  496.142637] CR2: 000000005e821edd CR3: 0000000108926006 CR4: 0000000000370ef0
[  496.145739] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[  496.148654] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[  496.152097] Call Trace:
[  496.153696]  <TASK>
[  496.154611]  switch_domain+0x58/0xf0 [tyche]
[  496.156269]  switch_enclave+0x2b/0x40 [tyche]
[  496.157676]  tyche_ioctl+0xc5/0x240 [tyche]
[  496.159297]  __x64_sys_ioctl+0x87/0xc0
[  496.160848]  do_syscall_64+0x3c/0x90
[  496.163285]  entry_SYSCALL_64_after_hwframe+0x72/0xdc
[  496.165299] RIP: 0033:0x7f09b872caff
[  496.166615] Code: 00 48 89 44 24 18 31 c0 48 8d 44 24 60 c7 04 24 10 00 00 00 48 89 44 24 08 48 8d 44 24 20 48 89 44 24 10 b8 10 00 00 00 0f 05 <41> 89 c0 3d 00 f0 ff ff 77 1f 48 8b 44 24 18 64 48 2b 04 25 28 00
[  496.173123] RSP: 002b:00007ffcc4a7b230 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
[  496.175928] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f09b872caff
[  496.178737] RDX: 00007ffcc4a7b2a8 RSI: 0000000080086166 RDI: 0000000000000004
[  496.181613] RBP: 00007ffcc4a7b2b0 R08: 00007f09b882da70 R09: 000000007fffffff
[  496.184727] R10: 000056392f6bf140 R11: 0000000000000246 R12: 00007ffcc4a7b4b8
[  496.188411] R13: 000056392f6bd4bf R14: 0000000000000000 R15: 00007f09b8883040
[  496.189825]  </TASK>
[  496.190737] Modules linked in: tyche(O)
[  496.191301] CR2: 000000005e821edd
[  496.192048] ---[ end trace 0000000000000000 ]---
[  496.192715] RIP: 0010:tyche_switch+0x3b/0x5d [tyche]
[  496.193919] Code: 00 00 ba 09 00 00 00 45 31 c0 55 53 51 52 41 52 41 53 41 54 41 55 41 56 41 57 9c fa 48 89 d0 48 8b 39 4c 89 c6 4d 89 cb 0f 01 <c1> 9d 41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 5a 59 5b 5d 48 89 c2 49
[  496.196802] RSP: 0018:ffffc9000070be08 EFLAGS: 00010202
[  496.197671] RAX: 000000000040bfdc RBX: ffff88810b87abe0 RCX: ffff88810f1a9d80
[  496.199016] RDX: 00000000004011eb RSI: 0000000000000000 RDI: 000000000040bfdc
[  496.201411] RBP: 000000000040bf9c R08: 0000000000000000 R09: 0000000000000000
[  496.203625] R10: 0000000000000000 R11: 0000000000000000 R12: ffff88811c001800
[  496.205468] R13: 00007ffcc4a7b2a8 R14: ffff88811437de00 R15: 0000000000000000
[  496.207915] FS:  00007f09b860f740(0000) GS:ffff888154600000(0000) knlGS:0000000000000000
[  496.209232] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  496.210165] CR2: 000000005e821edd CR3: 0000000108926006 CR4: 0000000000370ef0
[  496.211455] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[  496.212584] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Killed
```
