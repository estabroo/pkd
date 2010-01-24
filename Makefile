#!/usr/bin/make

PKD_VERSION = 1.6

KVERSION=$(shell uname -r)
KERNEL_DIR=/lib/modules/$(KVERSION)/build

IPTABLES := $(shell which iptables)
IPT_VERSION := $(shell $(IPTABLES) -V)
IPT_VERS := $(subst iptables v,,${IPT_VERSION})
IPT_SVERS := $(shell echo $(IPT_VERS) | cut -d. -f1,2)
ifeq ($(IPT_VERS), '')
	IPT_VERS := 1.3.8
	IPT_SVERS := 1.3
endif
IPT_VERS_STRIP := $(strip $(IPT_SVERS))

ifeq ($(DESTDIR), '')
	DESTDIR=/usr/local
endif

ifeq ($(IPT_VERS_STRIP),1.3)
	IPT_CFLAGS = -I.
else
	IPT_CFLAGS = -I. -I./include-$(IPT_VERS) -I${KERNEL_DIR}/include -DIPT14=1
endif


libXTABLES_T := $(shell strings $(IPTABLES) | grep libxtables)
libXTABLES := $(strip $(libXTABLES_T))
ifeq ($(libXTABLES), )

	LIBDIR_T := $(shell strings $(IPTABLES) | grep -A 1 TABLES | grep ^/ )
	LIBDIR := $(strip $(LIBDIR_T))

	XTABLES_T := $(shell strings $(IPTABLES) | grep XTABLES)
	XTABLES := $(strip $(XTABLES_T))
	ifeq ($(XTABLES), XTABLES_LIBDIR)
		IPT_CFLAGS += -DXTABLES=1
	endif
else
	IPT_CFLAGS += -DXTABLES=1 -DLIBXTABLES=1
	LIBDIR_T := $(shell strings /lib/$(libXTABLES) | grep -A 1 TABLES | grep ^/ )
	LIBDIR := $(strip $(LIBDIR_T))
	LIBID_T := $(shell strings /lib/$(libXTABLES) | grep -m 1 libxtables.so )
	LIBID := $(strip $(LIBID_T))
	ifneq ($(LIBID), )
		IPT_CFLAGS += -DXTABLES_VERSION=$(LIBID)
	endif
endif
	

.PHONY: all
all: knock lib module

.PHONY: install
install: install-lib install-module
	depmod -a

.PHONY: dist
dist:
	@mkdir pkd-${PKD_VERSION}
	@cp -a include* example.ipt_pkd.ini knock.py GPLv2 Changelog DISCLAIMER README knock.c libipt_pkd.c pkd.c ipt_pkd.h Makefile pkd-${PKD_VERSION}
	tar -czvf pkd-${PKD_VERSION}.tgz pkd-${PKD_VERSION}
	@rm -rf pkd-${PKD_VERSION}
	sha1sum pkd-${PKD_VERSION}.tgz > pkd-${PKD_VERSION}.tgz.sha1sum

clean:
	rm -rf *.o *.so *.ko *.mod.c .*cmd .tmp* Module.symvers knock *.tgz *.sha1sum

knock.o: knock.c
	${CC} -g -c $+

knock: knock.o
	${CC} -o $@ $+ -lssl

libipt_pkd.o: libipt_pkd.c
	echo ${IPT_VERS}
	${CC} ${IPT_CFLAGS} -rdynamic -fPIC -c -DIPTABLES_VERSION=\"${IPT_VERS}\" -DPKD_VERSION=\"${PKD_VERSION}\" -o $@ $+

libipt_pkd.so: libipt_pkd.o
	${CC} -fPIC -shared -o $@ $+

.PHONY: lib
lib: libipt_pkd.so

.PHONY: install-lib
install-lib: lib
	install -s -m 0644 -o root -g root -t $(LIBDIR) libipt_pkd.so

# below is the stuff for the kernel make stuff to work on
obj-m := ipt_pkd.o
ipt_pkd-objs := pkd.o

EXTRA_CFLAGS = -DPKD_VERSION=\"${PKD_VERSION}\"
module: pkd.c
	$(MAKE) modules -C $(KERNEL_DIR) M=$(CURDIR) KERNELRELEASE=$(KVERSION)

install-module: module
	$(MAKE) modules_install -C $(KERNEL_DIR) M=$(CURDIR) KERNELRELEASE=$(KVERSION)

