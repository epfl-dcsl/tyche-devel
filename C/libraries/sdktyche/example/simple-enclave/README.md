# Simple Enclave Example


## How to run

This application runs by default or if you type:

```
./simple_enclave
```

### What it does

The application loads the enclave and performs two calls to it, printing two different messages.

### Sample output

```
dev@tyche:/tyche/programs$ ./simple_enclave
[LOG @../../..//sdktyche/loader/lib.c:269 parse_domain] Parsed tychools binary
[LOG @untrusted/main.c:92 main] The binary enclave has been loaded!
[LOG @untrusted/main.c:100 main] Calling the enclave, good luck!
[LOG @untrusted/main.c:49 hello_world] Executing HELLO_WORLD enclave

[ERROR | capa_engine::domain] Removing from a core in which the domains was NOT executing
[LOG @untrusted/main.c:56 hello_world] First enclave message:
Hello World!

[LOG @untrusted/main.c:63 hello_world] Second enclave message:
Bye Bye! :)!

[LOG @untrusted/main.c:70 hello_world] All done!
[LOG @untrusted/main.c:106 main] Done, have a good day!

```
