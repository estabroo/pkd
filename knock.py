#!/usr/bin/python2.5

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

optparser.set_usage("Usage: %prog [options] place_to_knock ...")
optparser.epilog = "place_to_knock is the section name in the config file where the host and key are found"
    
(options, args) = optparser.parse_args()

config = ConfigParser()
read = config.read(options.configfile)
if (len(read) == 0):
    print "no config files found, default config file is ~/.ipt_pkd.ini\n"
    exit(0)

sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('', 0))

for site in (args):
    if (config.has_section(site)):
        host = config.get(site, "host")
        port = randint(1024, 50000)
        key = config.get(site, "key")

        if (key.startswith("0x")):
            bkey = a2b_hex(key[2:])
        else:
            bkey = key

        l = len(bkey)
        for i in range(0, 40-l):
            bkey += '\0'
        
        p = "PKD0" + pack("<II", int(time.time()), 0) + pack("<III", getrandbits(32), getrandbits(32), getrandbits(32))
        ssum = p + bkey
        m = hashlib.sha256()
        m.update(ssum);
        d = m.digest()

        packet = p + d;
        sock.sendto(packet, (host, port))

        print "Sent knock packet to", host
    else:
        print "Section [", site, "] doesn't exist in", options.configfile


