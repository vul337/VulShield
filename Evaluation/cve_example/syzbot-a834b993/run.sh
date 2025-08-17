#!/bin/sh
qemu-system-x86_64   -m 4G  -kernel ./linux_kernel/linux-7bf70dbb18820b37406fdfa2aaf14c2f5c71a11a/arch/x86/boot/bzImage 
  -initrd ./busybox-1.31.0/rootfs.img \
  -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init \
kcsan.enable=1 kcsan.permissive=1 kcsan.strict=0 \
kcsan.ignore_atomic=0 kcsan.report_value_change_only=0" \
  -nographic \
  -gdb tcp::1234 \
  -smp 8 \
  -serial mon:stdio \
  -serial tcp::4444,server,nowait \
  -net user,hostfwd=tcp::5555-:23 \
  -net nic
