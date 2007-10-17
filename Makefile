#!/usr/bin/make

KVERSION=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KVERSION)/build

IPT_VERSION := $(shell /sbin/iptables -V)
IPT_VERS = $(subst iptables v,,${IPT_VERSION})
ifeq ($(IPT_VERS), '')
	IPT_VERS = 1.3.8
endif

DESTDIR=/usr/local
#INSTALL_MOD_PATH:=/tmp

EXTRA_CFLAGS := -I.

all: knock lib module
install: install-lib install-module

clean:
	rm -rf *.o *.so *.ko *.mod.c .*cmd .tmp* Module.symvers knock

knock: knock.o
	${CC} -o $@ $+ -lssl

libipt_pkd.o: libipt_pkd.c
	${CC} -rdynamic -fPIC -c -DIPTABLES_VERSION=\"${IPT_VERS}\" -o $@ $+

libipt_pkd.so: libipt_pkd.o
	${CC} -fPIC -shared -o $@ $+

.PHONY: lib
lib: libipt_pkd.so

install-lib: lib
	install -s -m 0644 -o root -g root -t /lib/iptables libipt_pkd.so

obj-m := ipt_pkd.o
ipt_pkd-objs := pkd.o

module: pkd.c
	$(MAKE) modules -C $(KERNEL_DIR) M=$(CURDIR) KERNELRELEASE=$(KVERSION)

install-module: module
	$(MAKE) modules_install -C $(KERNEL_DIR) M=$(CURDIR) KERNELRELEASE=$(KVERSION)

