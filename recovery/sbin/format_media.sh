#!/sbin/sh
/sbin/busybox fdisk /dev/block/avnftl8 < /etc/fdisk.cmd

/sbin/toolbox newfs_msdos /dev/block/avnftl8
