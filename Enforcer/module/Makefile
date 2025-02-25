MODULES_DIR ?= /lib/modules/$(shell uname -r)
#MODULES_DIR ?= /home/clive/linux_kernel/linux-4.11/
#MODULES_DIR ?= /home/clive/linux_kernel/linux-5.5-kasan/
#KERNEL_DIR ?= ~/linux_kernel/src/linux-4.11
#KERNEL_DIR ?=~/linux_kernel/src/build/CVE-2017-8890/linux
#KERNEL_DIR ?= ~/linux_kernel/src/linux-5.5-kasan
# KERNEL_DIR ?= ~/linux_kernel/src/build/CVE-2017-15649/linux-4.13
KERNEL_DIR ?= ${MODULES_DIR}/build
CURRENT_PATH:=$(shell pwd)

ccflags-y := -I.

obj-m += vul_shield.o

vul_shield-objs:= vul_patch_module.o  shield_quarantine.o verify.o

all:
	make -C ${KERNEL_DIR} M=$(CURRENT_PATH)
modules:
	make -C ${KERNEL_DIR} M=$(CURRENT_PATH) $@
clean:
	make -C ${KERNEL_DIR} M=$(CURRENT_PATH) clean 
