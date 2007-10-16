#!/usr/bin/make

KVERSION=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KVERSION)/build

DESTDIR=/usr/local
#INSTALL_MOD_PATH:=/tmp

EXTRA_CFLAGS := -I.

all: lib module
install: install-lib install-module

clean:
	rm -rf *.o *.so *.ko *.mod.c .*cmd .tmp*

libipt_pkd.o: libipt_pkd.c
	${CC} -c -DIPTABLES_VERSION=\"1.3.8\" -o $@ $+

libipt_pkd.so: libipt_pkd.o
	${LD} -shared -o $@ $+

.PHONY: lib
lib: libipt_pkd.so

install-lib: lib
	${CP} -a libipt_pkd.so /lib/iptables/

obj-m := ipt_pkd.o
ipt_pkd-objs := pkd.o

module: pkd.c
	$(MAKE) modules -C $(KERNEL_DIR) M=$(CURDIR) KERNELRELEASE=$(KVERSION)

install-module: module
	$(MAKE) modules_install -C $(KERNEL_DIR) M=$(CURDIR) KERNELRELEASE=$(KVERSION)

