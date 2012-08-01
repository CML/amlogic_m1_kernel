#!/sbin/sh
mount /dev/block/avnftl8 /emmc
dd if=/dev/zero of=/emmc/.swap bs=16384 count=16384
mkswap /emmc/.swap
umount /emmc
