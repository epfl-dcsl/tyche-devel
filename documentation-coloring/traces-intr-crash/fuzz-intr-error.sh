#!/bin/bash
# Starts QEMU in the background and monitors its output
# If we detect that the VM has not successfuly booted after a ceratin timelimited
# We copy its output to a permanent file, kill the VM and start again
# I used this to debug some infrequently occuring crashes during boot
# In the Qemu command, only the `-serial file:qemu-serial.txt -monitor tcp:127.0.0.1:4444,server,nowait`
# parameters are crucial. We use the qemu-serial.txt file to monitor the VM's output and the monitor interface to
# kill the VM if it gets stuck

touch ./qemu-serial.txt
ITERATION_COUNT=0
while true; do
    # Start QEMU in the background
    /home/t-lucawilke/build-qemu/qemu-system-x86_64  -smp 1 -drive format=raw,file=/home/t-lucawilke/tyche-devel/target/x86_64-unknown-kernel/debug/boot-uefi-s1.img -bios OVMF-pure-efi.fd --no-reboot -nographic -device isa-debug-exit,iobase=0xf4,iosize=0x04 -device intel-iommu,intremap=on,aw-bits=48 -cpu host,+kvm -machine q35 -accel kvm,kernel-irqchip=split -m 32G -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 -device e1000,netdev=net0 -drive file=ubuntu.qcow2,format=qcow2,media=disk -serial file:qemu-serial.txt -monitor tcp:127.0.0.1:4444,server,nowait &

    last_mod_time=$(stat -c %Y "./qemu-serial.txt")
    # Wait until the serial output file contains the login string
    while ! grep -q "tyche-vm login" "./qemu-serial.txt"; do
        sleep 1
        current_mod_time=$(stat -c %Y "./qemu-serial.txt")
        if [[ "$current_mod_time" -eq "$last_mod_time" ]]; then
            # Check if the file has not changed given amount of seconds
            if (( $(date +%s) - last_mod_time >= 30 )); then
                echo "timeout"
                cp "./qemu-serial.txt" "stuck-run-$ITERATION_COUNT.txt"
                #break out of while loop -> this will terminate current run and continue with the next one
                break
            fi
            else
                last_mod_time="$current_mod_time"
        fi
    done

    # Terminate QEMU via the monitor
    echo quit | nc localhost 4444

    # Reset the serial output file
    echo "" > ./qemu-serial.txt
    echo "" > ./monitor-log.txt

    # Optional: Add a short sleep before restarting the loop
    sleep 1
    ITERATION_COUNT=$((ITERATION_COUNT +1))
    echo "finished iteration $ITERATION_COUNT"
    # if [[ $((ITERATION_COUNT % 2)) == 0 ]]; then
    #     echo "cleaning"
    #     cargo clean
    #     just build-linux-x86
    # fi
done
