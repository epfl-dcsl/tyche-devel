#!/bin/bash

if [[ $(lsmod | grep kvm_intel) ]]; then
  sudo modprobe -r kvm_intel
fi
if [[ $(lsmod | grep kvm_themis) ]]; then
  echo "kvm_themis already loaded."
else
  sudo modprobe kvm_themis
fi
