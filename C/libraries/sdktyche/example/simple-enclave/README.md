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
