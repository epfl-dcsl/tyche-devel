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

##
### Install disk
### We have a disk B with 2 partitions for now
#mknod /dev/vda15 b 254 15     #This is the EFI partition, leaving commented
#mknod /dev/vda1 b 254 1
###
#### Create new root
#mkdir /newroot
#mount /dev/vda1 /newroot || error
#ls /newroot/sbin || error
###
#### Switch root
#exec switch_root /newroot /sbin/init || error

#exec /bin/sh

error
