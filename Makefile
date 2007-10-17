#!/usr/bin/make

PKD_VERSION = 0.3

KVERSION=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KVERSION)/build

IPT_VERSION := $(shell /sbin/iptables -V)
IPT_VERS = $(subst iptables v,,${IPT_VERSION})
ifeq ($(IPT_VERS), '')
	IPT_VERS = 1.3.8
endif

DESTDIR=/usr/local

EXTRA_CFLAGS := -I.

.PHONY: all
all: knock lib module

.PHONY: install
install: install-lib install-module

.PHONY: dist
dist:
	@mkdir pkd-${PKD_VERSION}
	@cp -a README knock.c libipt_pkd.c pkd.c ipt_pkd.h Makefile pkd-${PKD_VERSION}
	tar -czvf pkd-${PKD_VERSION}.tgz pkd-${PKD_VERSION}
	@rm -rf pkd-${PKD_VERSION}
	sha1sum pkd-${PKD_VERSION}.tgz > pkd-${PKD_VERSION}.tgz.sha1sum

clean:
	rm -rf *.o *.so *.ko *.mod.c .*cmd .tmp* Module.symvers knock *.tgz *.sha1sum

knock: knock.o
	${CC} -o $@ $+ -lssl

libipt_pkd.o: libipt_pkd.c
	${CC} -rdynamic -fPIC -c -DIPTABLES_VERSION=\"${IPT_VERS}\" -o $@ $+

libipt_pkd.so: libipt_pkd.o
	${CC} -fPIC -shared -o $@ $+

.PHONY: lib
lib: libipt_pkd.so

.PHONY: install-lib
install-lib: lib
	install -s -m 0644 -o root -g root -t /lib/iptables libipt_pkd.so

# below is the stuff for the kernel make stuff to work on
obj-m := ipt_pkd.o
ipt_pkd-objs := pkd.o

module: pkd.c
	$(MAKE) modules -C $(KERNEL_DIR) M=$(CURDIR) KERNELRELEASE=$(KVERSION)

install-module: module
	$(MAKE) modules_install -C $(KERNEL_DIR) M=$(CURDIR) KERNELRELEASE=$(KVERSION)

