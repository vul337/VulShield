#!/bin/sh
mount -t debugfs none /sys/kernel/debug

echo on>/sys/kernel/debug/kcsan
echo whitelist > /sys/kernel/debug/kcsan
echo '!netlink_insert' > /sys/kernel/debug/kcsan
echo '!netlink_getname' > /sys/kernel/debug/kcsan
