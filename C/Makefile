all:

ubuntu_mount:
	sudo ./scripts/mount_ubuntu.sh mount ../ubuntu.qcow2 /tmp/mount

ubuntu_umount:
	sudo ./scripts/mount_ubuntu.sh umount ../ubuntu.qcow2 /tmp/mount

# Make sure you mount the disk first
update_disk:
	sudo chown --recursive $(shell whoami) /tmp/mount/tyche
	#make -B -C drivers/enclave install_disk
	#make -B -C drivers/tyche-capabilities install_disk
	#make -B -C programs/enclave install_disk
	#cp scripts/install_drivers.sh /tmp/mount/tyche/
	make -B -C drivers/tyche install_disk
	make -B -C libraries/sdkenclave/example/enclave install_disk
	cp scripts/install_drivers.sh /tmp/mount/tyche
