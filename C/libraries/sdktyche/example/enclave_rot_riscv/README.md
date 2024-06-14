# Simple Enclave Example


## How to run

This application runs by default or if you type:

```
./rot_enclave
```

### What it does

The application loads the enclave and performs numerous calls to it, in order to fetch the entire attestation from Tyche. It then queries Tychools to verify the attestation.

### Sample output
In the case the platform is equipped with a TPM:
```
[LOG @../../..//sdktyche/loader/lib.c:269 parse_domain] Parsed tychools binary
INFO | tyche::attestation_domain] Finished calculating the hash!
[LOG @untrusted/main.c:167 main] The binary enclave has been loaded!
[LOG @untrusted/main.c:176 main] Calling the enclave, good luck!
[LOG @untrusted/main.c:112 hello_world] Executing HELLO_WORLD enclave

[LOG @untrusted/main.c:117 hello_world] Nonce sent by the client is 2ff07b60
[LOG @untrusted/main.c:92 main] The binary enclave has been loaded!
[LOG @untrusted/main.c:97 read_tychools_response] Answer from tychools

[LOG @untrusted/main.c:101 read_tychools_response] Message was  verified

[LOG @untrusted/main.c:101 read_tychools_response] TPM PCR redigest is verified

[LOG @untrusted/main.c:101 read_tychools_response] TPM signature is verified
[LOG @untrusted/main.c:70 hello_world] All done!

[LOG @untrusted/main.c:106 main] Done, have a good day!
```

In the case a platform is without a TPM:

```
dev@tyche:/tyche/programs$ ./rot_enclave
[LOG @../../..//sdktyche/loader/lib.c:269 parse_domain] Parsed tychools binary
INFO | tyche::attestation_domain] Finished calculating the hash!
[LOG @untrusted/main.c:167 main] The binary enclave has been loaded!
[LOG @untrusted/main.c:176 main] Calling the enclave, good luck!
[LOG @untrusted/main.c:112 hello_world] Executing HELLO_WORLD enclave

[LOG @untrusted/main.c:117 hello_world] Nonce sent by the client is 2ff07b60
[LOG @untrusted/main.c:92 main] The binary enclave has been loaded!
[LOG @untrusted/main.c:97 read_tychools_response] Answer from tychools

[LOG @untrusted/main.c:101 read_tychools_response] Message was verified

[LOG @untrusted/main.c:101 read_tychools_response] TPM PCR redigest was not verified

[LOG @untrusted/main.c:101 read_tychools_response] TPM signature is verified
[LOG @untrusted/main.c:70 hello_world] All done!

[LOG @untrusted/main.c:106 main] Done, have a good day!
```

Note the signature verification still goes through and is validated. The contents of the PCR however, are not.
