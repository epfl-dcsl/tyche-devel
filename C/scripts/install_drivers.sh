#!/bin/bash

#sudo insmod /tyche/tyche-capabilities/tyche-capabilities.ko
#sudo insmod /tyche/tyche-enclave/tyche_enclave.ko
#sudo chmod 777 /dev/tyche_enclave
sudo insmod /tyche/drivers/tyche.ko
sudo chmod 777 /dev/tyche
