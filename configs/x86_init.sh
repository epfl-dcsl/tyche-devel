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

error_part3() {
  echo "Failed to mount on sdb2, try sdb3"
  umount /newroot
  mknod /dev/sdb3 b 8 19
  mount /dev/sdb3 /newroot || error
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
mount /dev/sdb2 /newroot || error_part3
ls /newroot/sbin || error_part3
###
#### Switch root
exec switch_root /newroot /sbin/init || error

exec /bin/sh
