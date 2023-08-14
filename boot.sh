#!/bin/bash
#
if pgrep -u "$(whoami)" swtpm;
then
	echo "TPM is running"
else
	echo "Starting TPM"
	mkdir -p /tmp/tpm-dev-$(whoami)/
	swtpm socket --tpm2 --tpmstate dir=/tmp/tpm-dev-$(whoami) --ctrl type=unixio,path=/tmp/tpm-dev-$(whoami)/sock &
fi

qemu-system-x86_64 \
  -smp 1 \
  -drive format=raw,file=/home/$(whoami)/vmxvmm/target/x86_64-unknown-kernel/debug/boot-uefi-s1.img \
  -bios OVMF-pure-efi.fd \
  --no-reboot \
  -nographic \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
  -device intel-iommu,intremap=on,aw-bits=48 \
  -device tpm-tis,tpmdev=tpm0 \
  -tpmdev emulator,id=tpm0,chardev=tpm-chardev \
  -cpu host,+kvm,+x2apic \
  -machine q35 \
  -accel kvm,kernel-irqchip=split \
  -m 50G \
  -chardev socket,id=tpm-chardev,path=/tmp/tpm-dev-$(whoami)/sock \
  -drive file=ubuntu.qcow2,format=qcow2,media=disk \
  -chardev socket,path=/tmp/gdb0,server=on,wait=off,id=gdb0
  # -gdb chardev:gdb0 # \
  # -S -s
