#!/bin/bash
# This script runs the VM in Qemu with the cloud-init config blob as a second argument
# Thus, cloud-init will apply the config

set -e 
VM_IMAGE=""
CONFIG_BLOB=""

usage() {
    echo "Usage:"
    echo "$0 [options]"
    echo "-vm-image    [Mandatory] qcow2 VM image"
    echo "-config-blob [Mandatory] cloud init config as .img file"
    exit
}


while [ -n "$1" ]; do
  case "$1" in
    -vm-image) VM_IMAGE="$2"
      shift
      ;;
    -config-blob) CONFIG_BLOB="$2"
      shift
      ;;
    *)
      usage
      exit
      ;;
  esac
  shift
done

if [ -z "$VM_IMAGE" ]; then
    usage
fi
if [ -z "$CONFIG_BLOB" ]; then
    usage
fi

qemu-system-x86_64 -smp 4 -m 2G -nographic -enable-kvm -hda "$VM_IMAGE" -hdb "$CONFIG_BLOB"