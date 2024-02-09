# Justfile, see documentation here:
# https://github.com/casey/just

toolchain           := "nightly-2023-12-01"
x86_64              := "--target configs/x86_64-unknown-kernel.json"
riscv               := "--target configs/riscv-unknown-kernel.json"
build_std           := "-Zbuild-std=core,alloc"
build_features      := "-Zbuild-std-features=compiler-builtins-mem"
cargo_args          := build_std + " " + build_features
x86-linker-script   := "RUSTFLAGS='-C link-arg=-Tconfigs/x86-linker-script.x'"
riscv-linker-script := "RUSTFLAGS='-C link-arg=-Tconfigs/riscv-linker-script.x'"
first-stage         := "--package s1 --features=s1/second-stage"
tyche               := "--package tyche"
rawc                := "--features=s1/guest_rawc"
linux               := "--features=s1/guest_linux"
no-guest            := "--features=s1/no_guest"
vga-s1              := "--features=s1/vga"
vga-s2              := "--features=tyche/vga"
bare-metal          := "--features=s1/bare_metal"
build_path          := justfile_directory() + "/builds"
tpm_path            := "/tmp/tpm-dev-" + env_var('USER')
default_dbg         := "/tmp/dbg-" + env_var('USER')
default_smp         := "1"
extra_arg           := ""

qemu-riscv			:= "../qemu/build/riscv64-softmmu/qemu-system-riscv64"
drive-riscv			:= "ubuntu-22.04.3-preinstalled-server-riscv64+unmatched.img"
kernel-riscv		:= "builds/linux-riscv/arch/riscv/boot/Image"
bios-riscv			:= "opensbi-stage1/build/platform/generic/firmware/fw_payload.bin"
dev-riscv			:= "-device virtio-rng-pci" 
bios-riscv-gdb		:= "opensbi-stage1/build/platform/generic/firmware/fw_payload.elf"

# Print list of commands
help:
	@just --list --unsorted

# Typecheck
check:
	@# Create an empty file if no second-stage has been compiled yet
	@mkdir -p target/x86_64-unknown-kernel/release
	@touch target/x86_64-unknown-kernel/release/tyche

	# Checking code...
	cargo check --package capa-engine
	cargo check --package vmx
	cargo check {{cargo_args}} {{x86_64}} {{first-stage}}
	cargo check {{cargo_args}} {{x86_64}} {{tyche}}
	cargo check {{cargo_args}} {{riscv}}  {{tyche}}

	# Checking formatting...
	cargo fmt --all -- --check

# Run the test suites
test:
	cargo test --package vmx
	cargo test --package capa-engine

	{{x86-linker-script}} cargo build {{cargo_args}} {{x86_64}} {{tyche}}
	{{riscv-linker-script}} cargo build {{cargo_args}} {{riscv}} {{tyche}}

# Format all rust code
format:
	cargo fmt

# Install the required dependencies
setup:
	# Installing Rust
	rustup target add x86_64-unknown-linux-musl
	rustup target add riscv64gc-unknown-linux-gnu
	rustup toolchain install {{toolchain}}
	rustup component add llvm-tools-preview --toolchain {{toolchain}}
	rustup component add rust-src --toolchain {{toolchain}}
	rustup target add x86_64-unknown-linux-musl --toolchain {{toolchain}}
	rustup component add rustfmt --toolchain {{toolchain}}

	# Download UEFI firmware for QEMU usage
	wget -O OVMF-pure-efi.fd https://github.com/rust-osdev/ovmf-prebuilt/releases/download/v0.20220719.209%2Bgf0064ac3af/OVMF-pure-efi.fd

	# -----------------------------------------------------------
	# IMPORTANT: You might need to perform some additional steps:
	# - Install `swtpm` (software TPM emulator)
	# - Install `qemu-system-misc` and `gcc-riscv64-linux-gnu` for RISC-V support

# Similar to `setup`, but more complete and targeted at ubuntu 22.04
setup-ubuntu:
	@just setup
	sudo apt install -y swtpm
	sudo apt install -y gcc-riscv64-linux-gnu
	sudo apt install -y libc6-dev-riscv64-cross
	sudo apt install -y qemu-system-misc

_common TARGET SMP ARG1=extra_arg ARG2=extra_arg:
	@just build
	@just _tpm
	-cargo run {{cargo_args}} {{x86_64}} {{first-stage}} {{TARGET}} -- --uefi --smp={{SMP}} {{ARG1}} {{ARG2}}

# Run without any guest
no-guest SMP=default_smp:
	@just _common {{no-guest}} {{SMP}}

# Run without guest, stop to wait for GDB session.
no-guest-dbg SMP=default_smp:
	@just _common {{no-guest}} {{SMP}} --stop --dbg_path={{default_dbg}}

# Run rawc guest
rawc SMP=default_smp:
	@just _common {{rawc}} {{SMP}}

# Run rawc guest, stop to wait for GDB session.
rawc-dbg SMP=default_smp:
	@just _common {{rawc}} {{SMP}} --stop --dbg_path={{default_dbg}}

# Run linux guest with UEFI
linux SMP=default_smp:
	@just _common {{linux}} {{SMP}}

# Run linux guest, stop to wait for GDB session.
linux-dbg SMP=default_smp:
	@just _common {{linux}} {{SMP}} --stop --dbg_path={{default_dbg}}

# Start a GDB session
gdb DBG=default_dbg:
	rust-gdb -q -ex "file target/x86_64-unknown-kernel/debug/s1" -ex "target remote {{DBG}}" -ex "source scripts/tyche-gdb.gdb"

# Build the monitor for x86_64
build:
	{{x86-linker-script}} cargo build {{cargo_args}} {{x86_64}} {{tyche}} --release
	cargo build {{cargo_args}} {{x86_64}} {{first-stage}}

# Build the monitor for RISC-V64
build-riscv:
	{{riscv-linker-script}} cargo build {{cargo_args}} {{riscv}} {{tyche}} --release
	./opensbi-stage1/run_build.sh

## ——————————————————————————— Linux Kernel Build ——————————————————————————— ##

build-linux-x86:
	@just _build-linux-common x86

build-linux-riscv:
	@just _build-linux-common riscv CROSS_COMPILE=riscv64-unknown-linux-gnu-

_build-linux-common ARCH CROSS_COMPILE=extra_arg:
	@just _setup-linux-config {{ARCH}}
	make -C ./linux ARCH={{ARCH}} O=../builds/linux-{{ARCH}} {{CROSS_COMPILE}} -j `nproc`
	@just _clean-linux-config {{ARCH}}

_build-linux-header-common ARCH CROSS_COMPILE=extra_arg:
	@just _setup-linux-config {{ARCH}}
	mkdir -p ./builds/linux-headers-{{ARCH}}
	make -C ./linux ARCH={{ARCH}} O={{build_path}}/linux-{{ARCH}} {{CROSS_COMPILE}} INSTALL_HDR_PATH={{build_path}}/linux-headers-{{ARCH}} headers_install
	@just _clean-linux-config {{ARCH}}

_setup-linux-config ARCH:
	cp ./configs/linux-{{ARCH}}.config  ./linux/arch/{{ARCH}}/configs/linux-{{ARCH}}_defconfig
	mkdir -p ./builds/linux-{{ARCH}}
	make -C ./linux ARCH={{ARCH}} O=../builds/linux-{{ARCH}} defconfig KBUILD_DEFCONFIG=linux-{{ARCH}}_defconfig

_clean-linux-config ARCH:
	rm ./linux/arch/{{ARCH}}/configs/linux-{{ARCH}}_defconfig

## —————————————————————————————— RamFS Build ——————————————————————————————— ##

build-busybox-x86:
	@just _build-busybox-common x86

build-busybox-riscv:
	@just _build-linux-header-common riscv CROSS_COMPILE=riscv64-unknown-linux-gnu-
	@just _build-busybox-common riscv CROSS_COMPILE=riscv64-unknown-linux-gnu-

_build-busybox-common ARCH CROSS_COMPILE=extra_arg:
	mkdir -p ./builds/busybox-{{ARCH}}
	cp ./configs/busybox-{{ARCH}}.config ./builds/busybox-{{ARCH}}/.config
	make -C ./busybox ARCH={{ARCH}} CFLAGS="-I{{build_path}}/linux-headers-{{ARCH}}/include" O=../builds/busybox-{{ARCH}}/ {{CROSS_COMPILE}} -j `nproc`
	make -C ./busybox ARCH={{ARCH}} O=../builds/busybox-{{ARCH}}/ {{CROSS_COMPILE}} PREFIX=../builds/ramfs-{{ARCH}} install
	cp ./configs/{{ARCH}}_init.sh ./builds/ramfs-{{ARCH}}/init

init-ramfs-x86:
	@just _init-ramfs-common x86

init-ramfs-riscv:
	@just _init-ramfs-common riscv

_init-ramfs-common ARCH:
	mkdir -p ./builds/ramfs-{{ARCH}}
	mkdir -p ./builds/ramfs-{{ARCH}}/bin
	mkdir -p ./builds/ramfs-{{ARCH}}/dev
	mkdir -p ./builds/ramfs-{{ARCH}}/sbin
	mkdir -p ./builds/ramfs-{{ARCH}}/etc
	mkdir -p ./builds/ramfs-{{ARCH}}/proc
	mkdir -p ./builds/ramfs-{{ARCH}}/sys/kernel/debug
	mkdir -p ./builds/ramfs-{{ARCH}}/usr/bin
	mkdir -p ./builds/ramfs-{{ARCH}}/usr/sbin
	mkdir -p ./builds/ramfs-{{ARCH}}/lib
	mkdir -p ./builds/ramfs-{{ARCH}}/lib64
	mkdir -p ./builds/ramfs-{{ARCH}}/mnt/root
	mkdir -p ./builds/ramfs-{{ARCH}}/root

	#
	#
	##### Please, run the following commands (with sudo) #####
	# This is necessary in order to create the `null`, `tty`, and `console` devices in the ramfs
	#
	# sudo mknod ./builds/ramfs-{{ARCH}}/dev/null c 1 3
	# sudo mknod ./builds/ramfs-{{ARCH}}/dev/tty c 5 0
	# sudo mknod ./builds/ramfs-{{ARCH}}/dev/console c 5 1

# Build the ramfs, packing all the userspace binaries
build-ramfs-x86:
	cargo build --package libtyche --target=x86_64-unknown-linux-musl --release
	cp target/x86_64-unknown-linux-musl/release/tyche ./builds/ramfs-x86/bin/

	@just build-linux-x86

# Build the monitor for bare metal platform
build-metal-no-guest:
	@just _common-metal {{no-guest}}

# Build the monitor for bare metal platform
build-metal-rawc:
	@just _common-metal {{rawc}}

# Build the monitor for bare metal platform
build-metal-linux:
	@just _common-metal {{linux}}

_common-metal TARGET:
	{{x86-linker-script}} cargo build {{cargo_args}} {{x86_64}} {{tyche}} --release
	-cargo run {{cargo_args}} {{x86_64}} {{first-stage}} {{TARGET}} {{bare-metal}} -- --uefi --no-run

# Build user-space programs
user-space:
	cargo build --package libtyche --target=x86_64-unknown-linux-musl --release

# Start the software TPM emulator, if not already running
_tpm:
	#!/usr/bin/env sh
	if pgrep -u $USER swtpm;
	then
		echo "TPM is running"
	else
		echo "Starting TPM"
		mkdir -p {{tpm_path}}/
		swtpm socket --tpm2 --tpmstate dir={{tpm_path}} --ctrl type=unixio,path={{tpm_path}}/sock &
	fi

run_riscv:
	{{qemu-riscv}} -nographic -drive "file={{drive-riscv}},format=raw,if=virtio" -cpu rv64,h=true -M virt -m 4G -bios {{bios-riscv}} -kernel {{kernel-riscv}} -append "root=/dev/vda1 rw console=ttyS0 earlycon=sbi quiet" -smp 1 {{dev-riscv}} 

run_riscv_4harts:
    {{qemu-riscv}} -nographic -drive "file={{drive-riscv}},format=raw,if=virtio" -cpu rv64,h=true -M virt -m 4G -bios {{bios-riscv}} -kernel {{kernel-riscv}} -append "root=/dev/vda1 rw console=ttyS0 earlycon=sbi quiet" -smp 4 {{dev-riscv}}

run_riscv_gdb: 
	{{qemu-riscv}} -nographic -drive "file={{drive-riscv}},format=raw,if=virtio" -cpu rv64,h=true -M virt -m 4G -bios {{bios-riscv}} -kernel {{kernel-riscv}} -append "root=/dev/vda1 rw console=ttyS0 earlycon=sbi quiet" -smp 1 {{dev-riscv}} -gdb tcp::1234 -S 
	
riscv_monitor_gdb:
	riscv64-unknown-linux-gnu-gdb -q -ex "file {{bios-riscv-gdb}}" -ex "target remote localhost:1234" -ex "b parse_and_load_elf" -ex "c" 

# The following line gives highlighting on vim
# vim: set ft=make :
