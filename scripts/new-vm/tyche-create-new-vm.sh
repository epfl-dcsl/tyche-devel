#!/bin/bash
# Create a new VM disk based on ubuntu cloud image as well as an
# cloud init "config blob". The VM has to be started once, with the 
# config blob as VM disk as drive -hda and the config blow as drive -hdb
# This will apply the config
set -e 

SCRIPT_DIR=$(dirname "$0")


BASE_DISK="/tmp/jammy-server-base.qcow2"
BUILD_DIR="."
NEW_VM=
#size of the qcow2 disk image in GB
SIZE=20
OWNER_PUBKEY_PATH=""

usage() {
  echo "Usage:"
  echo "$0 [options]"
  echo "-image-name                 [Mandatory] Image name for the VM image. Must end in .qcow2"
  echo "-build-dir PATH             [Optional] Path where all files will be written to (default '.')"
  echo "-size INTEGER               [Optional]  Size for the qcow2 disk image in GB. Defaults to 20"
  echo "-owner-pubkey PATH          [Optional]  Path to SSH public key that gets added to authorized keys. If not specified, we generate a new keypair"
  echo "-server-privkey PATH        [Optional]  Path to SSH private key that is used for the OpenSSH server. If not specified, we generate a new keypair"
}


if ! command -v mkpasswd &> /dev/null
then
  echo "mkpasswd command not found."
  echo "You can install it with sudo apt install whois"
  exit 1
fi

while [ -n "$1" ]; do
  case "$1" in
    -image-name) NEW_VM="$2"
      shift
      ;;
    -build-dir) BUILD_DIR="$2"
      shift
      ;;
    -owner-pubkey) OWNER_PUBKEY_PATH="$2"
      shift
      ;;
    -size)
      SIZE="$2"
      shift
      ;;
    *)
      usage
      exit
      ;;
  esac
  shift
done

BUILD_DIR=$(realpath "$BUILD_DIR")
mkdir -p "$BUILD_DIR"
if [ ! -d "$BUILD_DIR" ]; then
  echo "Invalid build dir $BUILD_DIR"
  usage
  exit 1
fi

if [ -z "$NEW_VM" ]; then
  echo "-out-vm-image is a mandatory parameter"
  usage
  exit 1
fi


#Download base image
if [ ! -f "$BASE_DISK" ]; then
  wget -O "$BASE_DISK" https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
fi


#Create a copy with a larger disk. Note that qcow2 is lazy allocated, i.e. this
#does not produce a 20G file
cp "$BASE_DISK" "$BUILD_DIR/$NEW_VM"
qemu-img resize "$BUILD_DIR/$NEW_VM" "${SIZE}G"

KEYS_PATH="$BUILD_DIR/keys"

#If no pubkeys were specified, generate them
if [ -z "$OWNER_PUBKEY_PATH" ]; then
  mkdir -p "$KEYS_PATH"
  DEFAULT_PATH="$KEYS_PATH/ssh-key-vm-owner"
  echo "No owner public ssh key provided. Generating a new keypair at $DEFAULT_PATH"
  ssh-keygen -t ed25519 -N "" -f "$DEFAULT_PATH"
  OWNER_PUBKEY_PATH="${DEFAULT_PATH}.pub"
fi


#Query Username and password
echo "Enter username"
read -r USERNAME

echo "Enter Password"
PWHASH=$(mkpasswd --method=SHA-512 --rounds=4096)


#Create cloud-init "user-data" config based on template
echo "Creating config file"

CONFIG_PATH=$BUILD_DIR/config
mkdir -p "$CONFIG_PATH"

USER_DATA=$CONFIG_PATH/user-data

cp "$SCRIPT_DIR/template-user-data" "$USER_DATA"
sed -i "s#<USER>#$USERNAME#g" "$USER_DATA"
sed -i "s#<PWDHASH>#$PWHASH#g" "$USER_DATA"
USER_PUBKEY=$(cat "$OWNER_PUBKEY_PATH")
sed -i "s#<USER_PUBKEY>#$USER_PUBKEY#g" "$USER_DATA"

OUT_CFG_BLOB="$BUILD_DIR/config-blob.img"
echo "Writing config blow to $OUT_CFG_BLOB"
touch "$CONFIG_PATH"/meta-data
touch "$CONFIG_PATH"/network-config
genisoimage \
    -output "$OUT_CFG_BLOB" \
    -volid cidata -rational-rock -joliet \
    "$USER_DATA" "$CONFIG_PATH"/meta-data "$CONFIG_PATH"/network-config
