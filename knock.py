#!/usr/bin/env python
#
# Copyright (c) 2007,2008,2013 Eric Estabrooks <eric@urbanrage.com>
#
# Implements basic client knock program in python
# host, key, tag data is stored in an ini style file
# by default ~/.ipt_pkd.ini
#

import os
import time
import hashlib
import binascii
import random
import socket
import argparse
import struct
from ConfigParser import ConfigParser

class Knock():
    def __init__(self, host, key, tag='PKD0', old=None):
        """Initialize with host = hostname or ip, key = hex string or byte string to use as the key, tag = 4 byte id, old if use old style for creating knock packet"""
        self.host = host
        if key.startswith("0x"):
            self.key = binascii.a2b_hex(key[2:])
        else:
            self.key = key
        l = len(self.key)
        for i in range(0, 40-l):
            self.key += '\0'
        self.key = self.key[:40]

        if len(tag) != 4:
            if not tag.startswith('0x'):
                raise ValueError("Invalid tag")
            else:
                self.tag = binascii.a2b_hex(tag[2:])
        else:
            self.tag = tag
        self.__use_old = old or False

    def knock(self, port=0):
        """send knock to given port or if no port given a randomly chosen one between 1024 and 50000"""
        try:
            rport = int(port)
        except TypeError:
            rport = 0
        if rport <= 0 or rport > 65535:
            rport = random.randint(1024, 50000)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', rport))

        bport = struct.pack("<BBBB", ((rport & 0xff00) >> 8), rport & 0xff, (rport & 0xff00) >> 8, rport & 0xff)
        p = self.tag + struct.pack("<II", int(time.time()), 0) + os.urandom(12)
        if self.__use_old:
            ssum = p + self.key
        else:
            ssum = bport + p + self.key
        m = hashlib.sha256()
        m.update(ssum);
        d = m.digest()

        packet = p + d;
        sock.sendto(packet, (self.host, rport))

def __main():
    """provide a default main program for the module"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default=os.path.expanduser("~/.ipt_pkd.ini"),
            help='name of config file containing host information')
    parser.add_argument('-k', '--key',
            help='key to use for this knock, overrides config entry if there is one')
    parser.add_argument('-t', '--tag',
            help='tag to use for this knock, overrides config entry if there is one')
    parser.add_argument('-p', '--port', type=int,
            help='port to use for this knock, overrides config entry if there is one')
    parser.add_argument('-q', '--quiet', action='store_true',
            help='be quiet about the operation')
    parser.add_argument('host', nargs='+',
            help='host to knock, or section name in config file')

    args = parser.parse_args()

    config = ConfigParser()
    read = config.read(args.config)
    if (len(read) == 0):
        if args.key is None:
            parser.error("You must either have a config file or specify a key")

    for site in (args.host):
        if (config.has_section(site)):
            host = config.get(site, "host")
            try:
                ports = config.get(site, "port");
                try:
                    port = int(ports)
                except:
                    port = None
            except:
            	port = None
            if args.port is not None:
                port = args.port

            key = config.get(site, "key")
            if args.key is not None:
                key = args.key

            try:
                tag = config.get(site, "tag");
            except:
                tag = "PKD0";
            if args.tag is not None:
                tag = args.tag

            try:
                config.get(site, "old");
                old = True
            except:
                old = False;

            k = Knock(host, key, tag, old)
            k.knock(port)

            if not args.quiet: print "Sent knock packet to", host
        else:
            if args.key is not None:
                key = args.key
                port = args.port
                tag = args.tag
                k = Knock(host, key, tag, False)
                k.knock(port)
                if not args.quiet: print "Sent knock packet to", host
            else:
                if not args.quiet: print "Section [", site, "] doesn't exist in", options.configfile


if __name__ == "__main__":
    __main()
