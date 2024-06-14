make ARCH=riscv ubuntu_mount || exit
make ARCH=riscv update_disk
make ARCH=riscv ubuntu_umount
