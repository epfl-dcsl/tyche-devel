#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs none /sys/kernel/debug

cat <<!


Boot took $(cut -d' ' -f1 /proc/uptime) seconds


 ________                    __                 
/        |                  /  |                
########/__    __   _______ ## |____    ______  
   ## | /  |  /  | /       |##      \  /      \ 
   ## | ## |  ## |/#######/ #######  |/######  |
   ## | ## |  ## |## |      ## |  ## |##    ## |
   ## | ## \__## |## \_____ ## |  ## |########/ 
   ## | ##    ## |##       |## |  ## |##       |
   ##/   ####### | #######/ ##/   ##/  #######/ 
        /  \__## |                              
        ##    ##/                               
         ######/                                


Welcome to Tyche


!

# Open a shell if switch root fail
error() {
    echo "Failed to switch root to Ubuntu"
    exec /bin/sh
}

error_nvme_part() {
  echo "Failed to mount"
  umount /newroot
  mknod /dev/nvme0n1p6 b 259 6
  mount /dev/nvme0n1p6 /newroot || error
}
##
### Install disk
### We have a disk B with 2 partitions for now
mknod /dev/sdb  b 8 16
mknod /dev/sdb1 b 8 17
mknod /dev/sdb2 b 8 18
###
#### Create new root
mkdir /newroot
mount /dev/sdb2 /newroot || error_nvme_part
ls /newroot/sbin || error_nvme_part
###
#### Switch root
exec switch_root /newroot /sbin/init || error

exec /bin/sh
