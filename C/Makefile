ARCH ?= x86

ifeq ($(ARCH), x86)
	DISK = "../ubuntu.qcow2"
	MOUNT_DIR = "/tmp/mount"
else ifeq ($(ARCH), riscv)
	DISK = "../ubuntu-22.04.3-preinstalled-server-riscv64+unmatched.img"
	MOUNT_DIR = "/tmp/ubuntu_riscv_mount/"
endif 

$(info ARCH="$(ARCH)")
$(info CROSS_COMPILE="$(CROSS_COMPILE)")

all:

ubuntu_mount:
	sudo ./scripts/mount_ubuntu.sh mount $(DISK) $(MOUNT_DIR) $(ARCH)

ubuntu_umount:
	sudo ./scripts/mount_ubuntu.sh umount $(DISK) $(MOUNT_DIR) $(ARCH)

ifeq ($(ARCH), x86)

PROGRAMGS_PATH ?= /tmp/mount/tyche/programs
TYCHOOLS_LOCAL_BIN_PATH ?= ../target/release

# Make sure you mount the disk first
update_disk:
	sudo chown --recursive $(shell whoami) /tmp/mount/tyche
	make ARCH=x86 KVM=0 DISK_PATH=/tmp/mount/tyche/programs/sdk_tyche -B -C libraries/sdktyche/example/app-selector install_disk
	make ARCH=x86 KVM=0 DISK_PATH=/tmp/mount/tyche/programs/sdk_tyche -B -C libraries/sdktyche/example/simple-enclave install_disk
	make ARCH=x86 KVM=0 DISK_PATH=/tmp/mount/tyche/programs/sdk_tyche -B -C libraries/sdktyche/example/simple-sandbox install_disk
	make ARCH=x86 KVM=0 DISK_PATH=/tmp/mount/tyche/programs/sdk_tyche -B -C libraries/sdktyche/example/redis install_disk
	make ARCH=x86 KVM=0 DISK_PATH=/tmp/mount/tyche/programs/sdk_tyche -B -C libraries/sdktyche/example/ping-pong install_disk
	make ARCH=x86 KVM=0 DISK_PATH=/tmp/mount/tyche/programs/sdk_tyche -B -C libraries/sdktyche/example/encr-redis install_disk
	make ARCH=x86 KVM=0 DISK_PATH=/tmp/mount/tyche/programs/sdk_tyche -B -C libraries/sdktyche/example/simple-attestation install_disk
	#make ARCH=x86 KVM=0 DISK_PATH=/tmp/mount/tyche/programs/sdk_tyche -B -C libraries/sdktyche/example/ssl-redis install_disk
	make ARCH=x86 KVM=0 DISK_PATH=/tmp/mount/tyche/ubench/sdk_tyche -B -C microbenchmarks/ install_disk
	make ARCH=x86 KVM=1 DISK_PATH=/tmp/mount/tyche/programs/sdk_kvm -B -C libraries/sdktyche/example/app-selector install_disk
	make ARCH=x86 KVM=1 DISK_PATH=/tmp/mount/tyche/programs/sdk_kvm -B -C libraries/sdktyche/example/simple-enclave install_disk
	make ARCH=x86 KVM=1 DISK_PATH=/tmp/mount/tyche/programs/sdk_kvm -B -C libraries/sdktyche/example/simple-sandbox install_disk
	make ARCH=x86 KVM=1 DISK_PATH=/tmp/mount/tyche/programs/sdk_kvm -B -C libraries/sdktyche/example/redis install_disk
	make ARCH=x86 KVM=1 DISK_PATH=/tmp/mount/tyche/programs/sdk_kvm -B -C libraries/sdktyche/example/ping-pong install_disk
	make ARCH=x86 KVM=1 DISK_PATH=/tmp/mount/tyche/programs/sdk_kvm -B -C libraries/sdktyche/example/encr-redis install_disk
	make ARCH=x86 KVM=1 DISK_PATH=/tmp/mount/tyche/programs/sdk_kvm -B -C libraries/sdktyche/example/ssl-redis install_disk
	make ARCH=x86 KVM=1 DISK_PATH=/tmp/mount/tyche/ubench/sdk_kvm -B -C microbenchmarks/ install_disk
	make -B -C debug/test-contalloc/ install_disk
	make -B -C debug/test-bearssl/test-ssl-endpoint install_disk
	#make ARCH=x86 -B -C libraries/tyche-trusted-runtime install_disk
	#cp scripts/x86_64_install_drivers.sh /tmp/mount/tyche
	cp $(TYCHOOLS_LOCAL_BIN_PATH)/tychools $(PROGRAMGS_PATH)/tychools 
	
else ifeq ($(ARCH), riscv)

TYCHOOLS_RISCV_PATH ?= ../target/riscv64gc-unknown-linux-gnu/release
PROGRAMGS_PATH ?= /tmp/ubuntu_riscv_mount/tyche/programs
TYCHOOLS_LOCAL_BIN_PATH ?= ../target/release
TYCHOOLS_PATH ?= ../crates/tychools

update_disk: 
	sudo chown --recursive $(shell whoami) /tmp/ubuntu_riscv_mount/tyche
	make ARCH=riscv -B -C libraries/sdktyche/example/app-selector install_disk
	echo "Building tychools"
	cargo build --manifest-path $(TYCHOOLS_PATH)/Cargo.toml --release --target=riscv64gc-unknown-linux-gnu --config target.riscv64gc-unknown-linux-gnu.linker=\"riscv64-unknown-linux-gnu-gcc\" 
	make ARCH=riscv -B -C libraries/sdktyche/example/simple-enclave install_disk
	make ARCH=riscv -B -C microbenchmarks/ install_disk
	cp scripts/riscv64_install_drivers.sh /tmp/ubuntu_riscv_mount/tyche
	cp scripts/run_eapp.sh /tmp/ubuntu_riscv_mount/tyche
	cp $(TYCHOOLS_RISCV_PATH)/tychools $(PROGRAMGS_PATH)/tychools 

# Use the following when you see errors like the following during boot: 
### EXT4-fs error (device vda1): ext4_validate_block_bitmap:390: comm ext4lazyinit: bg 30: bad block bitmap checksum
### The superblock may have been corrupted and due to failing the checksum matching, the file system will get mounted in "ro" mode, which means you cannot write any logs to files, cannot copy the latest program builds to the /root and so on. 
# Neelu: This is undesirable. Make sure when running the VM you perform a clean poweroff or clean exit for all programs modifying the disk.  

fix_disk_superblock: 
	echo "fixing disk superblock"
	sudo losetup -P /dev/loop0 ../ubuntu-22.04.3-preinstalled-server-riscv64+unmatched.img 
	sudo fsck -f -y /dev/loop0p1 
	sudo losetup -d /dev/loop0 

endif

