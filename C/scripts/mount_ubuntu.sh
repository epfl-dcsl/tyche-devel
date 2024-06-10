#!/bin/sh

MOUNT_POINT="/tmp/mount_ubuntu_tyche"

DISK="$2"

mount_ubuntu_riscv() { 
  if [ ! -f "$DISK" ]; then
    echo "The file $DISK does not exist"
    exit 1
  fi

  modprobe loop max_part=8

  losetup -P /dev/loop66 $DISK

  if [ ! -f "$MOUNT_POINT" ]; then
    mkdir -p $MOUNT_POINT
  fi

  LOC=`fdisk /dev/loop66 -l | grep "G Linux" | awk '{print $1}'`
  mount $LOC $MOUNT_POINT
}

umount_ubuntu_riscv() {
  if [ ! -d "$MOUNT_POINT" ]; then
    echo "The folder $MOUNT_POINT does not exist."
    exit 1
  fi
  umount $MOUNT_POINT
  sudo losetup -d /dev/loop66
}

mount_ubuntu() {
  if [ ! -f "$DISK" ]; then
    echo "The file $DISK does not exist"
    exit 1
  fi
 
  modprobe nbd max_part=8
  
  qemu-nbd --connect=/dev/nbd0 $DISK
  
  LOC=`fdisk /dev/nbd0 -l | grep Linux | awk '{print $1}'`
  
  mkdir -p $MOUNT_POINT 
  mount $LOC $MOUNT_POINT
}

umount_unbuntu() {
  if [ ! -d "$MOUNT_POINT" ]; then
    echo "The folder $MOUNT_POINT does not exist."
    exit 1
  fi
  umount $MOUNT_POINT
  qemu-nbd --disconnect /dev/nbd0
  rmmod nbd
}

print_help() {
  echo "
usage: ./mount_ubuntu.sh [mount|umount] <file.qcow2> Opt<dest_folder>
If the dest_folder is not specified, we default to /tmp/mount_ubuntu_tyche.
DO NOT FORGET TO RUN WITH SUDO
  "
}

# Check if root
if [ "$(id -u)" != "0" ]; then
  echo "This script must run as root"
  print_help
  exit 1
fi

if [ ! "$3" = "" ]; then
  MOUNT_POINT="$3"
fi

if [ "$1" = "mount" ] && [ "$4" = "riscv" ]; then 
  mount_ubuntu_riscv
elif [ "$1" = "umount" ] && [ "$4" = "riscv" ]; then
  umount_ubuntu_riscv
elif [ "$1" = "mount" ]; then
  mount_ubuntu
elif [ "$1" = "umount" ]; then
  umount_unbuntu
else 
  print_help
fi
