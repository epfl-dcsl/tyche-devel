#!/bin/bash

#sudo insmod /tyche/tyche-capabilities/tyche-capabilities.ko
#sudo insmod /tyche/tyche-enclave/tyche_enclave.ko
#sudo chmod 777 /dev/tyche_enclave
insmod /tyche/drivers/tyche.ko
mknod /dev/tyche c 244 0
chmod 777 /dev/tyche
