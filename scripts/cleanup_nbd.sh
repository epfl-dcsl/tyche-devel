#!/bin/bash
#This script will disconnect all nbd devices and unload the driver

echo "Unmounting all nbd mounts"
mount | grep -i /dev/nbd | while read -r line;
do
MOUNT_POINT=$(echo "$line" | cut -d' ' -f3)
echo "Unmount $MOUNT_POINT.."
sudo umount "$MOUNT_POINT"
done

echo "Disconnecting all nbd devices..."
for i in /dev/nbd*;
do
    sudo qemu-nbd --disconnect "$i" 2>/dev/null || true
done

echo "Waiting for nbd to finish..."
sleep 2
sudo modprobe -r nbd || true
