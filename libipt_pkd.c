/*
 * Copyright (c) 2007 Eric Estabrooks <eric@urbanrage.com>
 *
 * Shared library add-on to iptables to add pkd matching support.
 * Use in conjuction with recent to provide iptable port knocking.
 *
 */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <iptables.h>
#include "ipt_pkd.h"

static struct option opts[] = {
	{ .name = "key",      .has_arg = 1, .flag = 0, .val = 'k' },
    { .name = "window",   .has_arg = 1, .flag = 0, .val = 'w' },
	{ .name = 0,          .has_arg = 0, .flag = 0, .val = 0   }
};

static void help(void) {
  printf("pkd v%s options:\n", PKD_VERSION,
           " --key key      up to %d byte shared key. use 0x to indicate the key in hex\n", PKD_KEY_SIZE,
           "                for example 0xab03be805172\n"
           " --window time  time in seconds +- that the packet can arrive in, defaults to 10 giving a 20 second window\n");
}
  
static void init(struct ipt_entry_match* match, unsigned int* nfcache) {
  struct ipt_pkd_info* info = (void *)(match)->data;

  memset(info->key, 0, sizeof(PKD_KEY_SIZE));
  strncpy(info->key,"AbC123kajsdf987nacva", PKD_KEY_SIZE);
  info->window = 10;
}

#define hex(a) ((a) >= 'a' ? ((a) - 'a' + 10) : ((a) - '0'))

static int parse(int c, char** argv, int invert, unsigned int* flags, const struct ipt_entry* entry,
                 unsigned int* nfcache, struct ipt_entry_match** match) {
  unsigned char        h;
  int                  i,j;
  int                  ret = 0;
  struct ipt_pkd_info* info = (void *)(*match)->data;
  
  switch (c) {
  case 'k' : {
    memset(info->key, 0, PKD_KEY_SIZE);
    if (optarg[0] == '0' && optarg[1] == 'x') {
      for (i=2,j=0; i < PKD_KEY_SIZE*2+2; i++,j++) {
        if (!isxdigit(optarg[i])) break;
        h = hex(tolower(optarg[i])) << 4;
        if (!isxdigit(optarg[++i])) { /* no lower nibble, make it a 0 */
          info->key[j++] = h;
          break;
        }
        h |= hex(tolower(optarg[i]));
        info->key[j] = h;
      }
    } else {
      strncpy(info->key, optarg, PKD_KEY_SIZE); /* its okay if the key isn't null terminated */
    }
    *flags = 1;
    ret = 1;
  }; break;
  case 'w' : {
    info->window = atol(optarg);
    if (info->window != 0) {
      ret = 1;
    }
    *flags = 1;
  }; break;
  default: ret = 0;
  };

  return ret;
}

static void final_check(unsigned int flags)
{

  if (!flags) {
    exit_error(PARAMETER_PROBLEM, "pkd: you must specify a key `--key key'");
  }
}

static void print(const struct ipt_ip* ip, const struct ipt_entry_match* match, int numeric) {
  struct ipt_pkd_info* info = (void *)match->data;
  int i;

  printf("pkd: ");
  if(info->key) {
    printf("key: 0x");
    for (i=0; i < PKD_KEY_SIZE; i++) {
      printf("%02x", info->key[i]);
    }
    printf(" ");
  }
  if (info->window) {
    printf("window: %lu ", info->window);
  }
}

static void save(const struct ipt_ip* ip, const struct ipt_entry_match* match) {
  struct ipt_pkd_info* info = (void *)match->data;
  int                  i;

  if (info->key) {
    printf("--key 0x");
    for (i=0; i < PKD_KEY_SIZE; i++) {
      printf("%02x", info->key[i]);
    }
    printf(" ");
  }
  if (info->window) {
    printf("--window %u ", info->window);
  }
}

static struct iptables_match pkd = { 
    .name          = "pkd",
    .version       = IPTABLES_VERSION,
    .size          = IPT_ALIGN(sizeof(struct ipt_pkd_info)),
    .userspacesize = IPT_ALIGN(sizeof(struct ipt_pkd_info)),
    .help          = help,
    .init          = init,
    .parse         = parse,
    .final_check   = final_check,
    .print         = print,
    .save          = save,
    .extra_opts    = opts
};

void _init(void) {
	register_match(&pkd);
}
