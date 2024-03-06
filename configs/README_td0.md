# TD0 configs and test labs

If everything went well, the command `just setup_lab_x86` should have correctly
set up your lab environment inside TD0.

Inside TD0 you should have the following file-tree:

```
/tyche
├── Makefile
├── programs
│   ├── sdk_kvm
│   │   ├── application_with_sandbox
│   │   ├── app_selector
│   │   ├── enclave_iso
│   │   └── simple_enclave
│   ├── sdk_tyche
│   │   ├── application_with_sandbox
│   │   ├── app_selector
│   │   ├── enclave_iso
│   │   └── simple_enclave
│   └── tychools
├── README.md
├── scripts
│   └── mod_switch.sh
└── vms
    ├── bios.bin
    └── bzImage
```
## Running anything with the KVM interface

The first thing you want to do is run `make install_driver`
This will replace the `kvm_intel` driver with `kvm_themis` for tyche.
It is required for all the programs under `/tyche/programs/sdk_kvm`.

## Running a tyche-vm td1 linux

The Makefile contains a rule `run_td1` that should do everything necessary to run td1 Linux.

:warning: you might be required to run it with sudo, i.e., `sudo make run_td1` :warning:.

## Running benchmarks with sdk-tyche

The sdk-tyche benchmarks use a version of the sdk that interacts with the tyche driver directly.
They are located under `/tyche/programs/sdk_tyche`.
For more information about each individual benchmark, please refer to the github
repo documentation under `C/librairies/sdktyche/example/`.

## Running benchmarks with sdk-kvm

The sdk-kvm benchmarks use a version of the sdk that interacts with KVM and kvm_themis.
They are located under `/tyche/programs/sdk_kvm`.

:warning: THEY REQUIRE THE `kvm_themis` driver to be loaded instead of `kvm_intel` :warning:.
This is achieved by running the `make install_driver` rule.
:warning: Depending on your ubuntu configuration, they might require sudo access rights :warning:.

For more information about each individual benchmark, please refer to the github
repo documentation under `C/librairies/sdktyche/example/`


