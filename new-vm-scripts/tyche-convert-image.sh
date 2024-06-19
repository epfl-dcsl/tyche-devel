#!/bin/bash
#This scripts ensures that the partitions are correctly setup

set -e

SRC_DEVICE=/dev/nbd0
SRC_FOLDER=$(mktemp -d)
DST_DEVICE=/dev/nbd1
DST_FOLDER=$(mktemp -d)

SRC_IMAGE=
DST_IMAGE=

NON_INTERACTIVE=""


SCRIPT_PATH=$(realpath "$(dirname "$0")")
. "$SCRIPT_PATH"/common.sh

trap clean_up EXIT

usage() {
  echo "$0 [options]"
  echo ""
  echo "-in PATH.qcow2            [Mandatory] Path to unencrypted input qcow2 disk image"
  echo "-out PATH.qcow2           [Optional] Path where the encrypted qcow2 disk is created. Defaults to the directory of the input file with -encrypted suffix"
  echo ""
  exit
}

if [ $# -eq 0 ]; then
  usage
fi

while [ -n "$1" ]; do
  case "$1" in
    -in) SRC_IMAGE="$2"
      shift
      ;;
    -out) DST_IMAGE="$2"
      shift
      ;;
    *)
      usage
      ;;
  esac
  shift
done

if [ -z "$DST_IMAGE" ]; then
  FILE_NO_EXTENSION="${SRC_IMAGE%.*}"
  DST_IMAGE="${FILE_NO_EXTENSION}-encrypted.qcow2"
fi

echo "Creating output image.."
create_output_image

echo "Initializing NBD module.."
initialize_nbd

echo "Finding root filesystem.."
find_root_fs_device
echo "Rootfs device selected: $SRC_ROOT_FS_DEVICE"

#echo "Formatting LUKS.."
#sudo cryptsetup luksFormat --type luks2 $DST_DEVICE $LUKS_PARAMS
#sudo cryptsetup luksOpen $DST_DEVICE snpguard_root

# Create the partitions. Tyche expects root file system on partition 2
# So we create a small dummy partition and a large second partition
# Create the GPT partition table and partitions
echo "Creation partions on $DST_DEVICE"
sudo parted --script "$DST_DEVICE" mklabel gpt \
    mkpart primary 1MiB 100MB \
    mkpart primary 100MB 100%

DST_ROOT_PARTITION="${DST_DEVICE}p2"

echo "Creating ext4 partition"
sudo mkfs.ext4 "$DST_ROOT_PARTITION"

echo "Mounting $SRC_ROOT_FS_DEVICE to $SRC_FOLDER"
sudo mount "$SRC_ROOT_FS_DEVICE" "$SRC_FOLDER"
echo "Mounting $DST_ROOT_PARTITION to $DST_FOLDER"
sudo mount $DST_ROOT_PARTITION "$DST_FOLDER"

echo "Copying files (this may take some time).."
copy_filesystem

echo "Success. Your disk image is at $DST_IMAGE"