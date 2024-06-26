# Tyche

## Setup

This project is controled through a _justfile_, this section details how to
setup the tools needed to build and run the monitors.

### Requirements

This project assumes an Intel x86_64 processor with VT-x capabilities in order
to build and run the x86_64 version. The risc-v version can be built from any
platform.

### rustup,  cargo, and just

Do not use the Ubuntu/debian distribution of `rustup` (from apt-get and/or snap) as this can cause a compilation problem with `rust-src`.

Instead, follow the instructions in `https://www.rust-lang.org/tools/install`

Check that `which rustc` and `which cargo` both point to `$HOME/.cargo/bin`

This project uses _justfiles_ as a command line runner (think makefiles but
without the build-system bits). 

To install `just` from sources: `cargo install just`.

To list available commands, run `just help`. 

To get started with this project, run `just setup`.

Later, just is used during development.  For instance, the monitor can be
built with `just build`.

### Linux Images

A standard, unmodified Linux image is provided to run on top of the monitor, as
well as a minimal busybox-based distribution. Both Linux and Busybox
configuratons can be found in the `configs/` folder.

In order to build the Linux kernel, follow those steps:

#### For x86_64

These steps assumes you are compiling from an x86_64 machine.

```sh
just init-ramfs-x86
just build-busybox-x86
just build-linux-x86
```

Then you can run the monitor with `just linux`

#### For risc-v

```sh
just init-ramfs-riscv
just build-busybox-riscv
just build-linux-riscv
```

## Usage

The VMM can easily be built and typechecked with:

```sh
# Build the monitor
just build

# Typecheck the monitor
just check
```

When running the VMM, multiple guests are available. By default, the selected
guest is `RawC`, a small C program that can be used for simple testing. To run
other guests, use:

```sh
# For RawC
just rawc

# For RawC with UEFI
just rawc-uefi

# For Linux
just linux
```

## UEFI boot

Our current bootloader supports both BIOS and UEFI boots, but UEFI is currently
required for Linux guests (for performance reasons). To boot with UEFI first
download the OVMF UEFI firmware at the root of this repo with:

```sh
wget https://github.com/rust-osdev/ovmf-prebuilt/releases/download/v0.20220719.209%2Bgf0064ac3af/OVMF-pure-efi.fd
```

And then run:

```sh
cargo krun-linux
```

## Booting Ubuntu

Ubuntu images are supported, to use one simple create a `.qcow2` image (follow a
tutorial for that), and add it at the root of this folder with the name
`ubuntu.qcow2`.

We also provide some scripts to quickly setup a new VM in the `scripts/new-vm` folder.
To use them, execute the following commands
```bash
cd ./scripts/new-vm
# Create VM image based on ubuntu cloud image
./tyche-create-new-vm.sh -image-name tyche-base.qcow2
# We need to start the VM once, to apply the cloud-init config. Terminate the VM after you reach the login prompt
./tyche-run-setup.sh -vm-image ./tyche-base.qcow2 -config-blob ./config-blob.img
# Finally, we need to adjust he partition layout, because tyche's init script is currently quite limited and expects things in a certain order. On the Prompt, double check that the selected filesytem is the "main" partition
./tyche-convert-image.sh -in tyche-base.qcow2 -out ../../ubuntu.qcow2
```
The final image is now ready to use and placed in `tyche-devel/ubuntu.qcow` where it gets picked up by the regular `just linux` command.
