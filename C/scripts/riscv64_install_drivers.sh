#!/bin/bash

# While using disk or running on VF2 

# #sudo insmod /tyche/drivers/tyche.ko

#sudo chmod 777 /dev/tyche
#sudo cp -r /tyche/programs /root
#sudo cp -r /tyche/benchmarks /root

# The commands to use in the ramfs are below, use them when running with the ramfs instead of the disk: 

#insmod /tyche/drivers/tyche.ko
#mknod /dev/tyche c 244 0
#chmod 777 /dev/tyche

# For XiangShan on FPGA with initramfs 
mount -t devtmpfs devtmpfs /dev
