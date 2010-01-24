install -m 0644 -o root -g root -t /lib/xtables libipt_pkd.so
mkdir /lib/modules/`uname -r`/extra
install -m 0400 -o root -g root -t /lib/modules/`uname -r`/extra ipt_pkd.ko
depmod -a
