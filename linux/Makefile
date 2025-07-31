# SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
# Copyright(c) 2016-21 Intel Corporation.

ifneq ($(KERNELRELEASE),)

obj-m += teevisor.o
teevisor-y := encl.o main.o driver.o ioctl.o protocol.o

else

KDIR := /lib/modules/$(shell uname -r)/build
KSYM_MMPUT_ASYNC := $(shell grep  "mmput_async\svmlinux\sEXPORT" $(KDIR)/Module.symvers)
KSYM_LOOKUP := $(shell grep "kallsyms_lookup_name\svmlinux\sEXPORT" $(KDIR)/Module.symvers)
EXTRA_CFLAGS :=
ifneq ($(KSYM_MMPUT_ASYNC),)
	EXTRA_CFLAGS += -DHAVE_MMPUT_ASYNC
endif
ifneq ($(KSYM_LOOKUP),)
	 EXTRA_CFLAGS += -DHAVE_KSYM_LOOKUP
endif

PWD  := $(shell pwd)
EXTRA_CFLAGS += -I$(PWD) -I$(PWD)/include -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now
EXTRA_LDFLAGS := -z noexecstack

default:
	$(MAKE) -C $(KDIR) M=$(PWD) LDFLAGS_MODULE="$(EXTRA_LDFLAGS)" CFLAGS_MODULE="$(EXTRA_CFLAGS)" modules

endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*.cmd *.o.ur-safe *.mod
