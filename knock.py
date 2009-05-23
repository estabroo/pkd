#!/usr/bin/python2.5
#
# Copyright (c) 2007,2008 Eric Estabrooks <eric@urbanrage.com>
#
# Implements basic client knock program in python
# host, key, tag data is stored in an ini style file
# by default ~/.ipt_pkd.ini
#

import os
import time
import hashlib
from binascii import *
from struct import *
from socket import *
from random import *
from ConfigParser import ConfigParser
from optparse import OptionParser

optparser = OptionParser()
optparser.add_option(
    "-c", "--config",
    default = os.path.expanduser("~/.ipt_pkd.ini"),
    dest="configfile", 
    help="location of config file")

optparser.add_option("-q", action="store_true", dest="quiet", default=False)

optparser.set_usage("Usage: %prog [options] place_to_knock ...")
optparser.epilog = "place_to_knock is the section name in the config file where the host and key are found"
    
(options, args) = optparser.parse_args()

config = ConfigParser()
read = config.read(options.configfile)
if (len(read) == 0):
    if not options.quiet: print "no config files found, default config file is ~/.ipt_pkd.ini\n"
    exit(0)


for site in (args):
    if (config.has_section(site)):
        host = config.get(site, "host")
        try:
            ports = config.get(site, "port");
            try:
                port = int(ports)
            except:
                port = randint(1024, 50000)
        except:
        	port = randint(1024, 50000)
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.bind(('', port))
        key = config.get(site, "key")
        try:
            tag = config.get(site, "tag");
        except:
            tag = "PKD0";
        try:
            old = config.get(site, "old");
        except:
            old = "new";

        if (key.startswith("0x")):
            bkey = a2b_hex(key[2:])
        else:
            bkey = key

        l = len(bkey)
        for i in range(0, 40-l):
            bkey += '\0'

        if (tag.startswith("0x")):
            btag = a2b_hex(tag[2:])
        else:
            btag = tag

        l = len(btag)
        for i in range(0, 4-l):
            btag += '\0'
        
        bport = pack("<BBBB", ((port & 0xff00) >> 8), port & 0xff, (port & 0xff00) >> 8, port & 0xff)
        p = btag + pack("<IIIII", int(time.time()), 0, getrandbits(32), getrandbits(32), getrandbits(32))
        if (old != "new"):
            ssum = p + bkey
        else:
            ssum = bport + p + bkey
        m = hashlib.sha256()
        m.update(ssum);
        d = m.digest()

        packet = p + d;
        sock.sendto(packet, (host, port))

        if not options.quiet: print "Sent knock packet to", host
    else:
        if not options.quiet: print "Section [", site, "] doesn't exist in", options.configfile


