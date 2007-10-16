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
	{ .name = "secret",   .has_arg = 1, .flag = 0, .val = 's' },
    { .name = "window",   .has_arg = 1, .flag = 0, .val = 'w' },
	{ .name = 0,          .has_arg = 0, .flag = 0, .val = 0   }
};

static void help(void) {
  printf("pkd v0.2 options:\n"
         " --secret secret   up to %d byte shared secret.\n", PKD_SECRET_SIZE);
}
  
static void init(struct ipt_entry_match* match, unsigned int* nfcache) {
  struct ipt_pkd_info* info = (void *)(match)->data;

  memset(info->secret, 0, sizeof(PKD_SECRET_SIZE));
  strncpy(info->secret,"AbC123kajsdf987nacva", PKD_SECRET_SIZE);
  info->window = 10;
}

static int parse(int c, char** argv, int invert, unsigned int* flags, const struct ipt_entry* entry,
                 unsigned int* nfcache, struct ipt_entry_match** match) {
  struct ipt_pkd_info* info = (void *)(*match)->data;
  int                  ret = 0;

  switch (c) {
  case 's' : {
    memset(info->secret, 0, PKD_SECRET_SIZE);
    strncpy(info->secret, optarg, PKD_SECRET_SIZE);
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
    exit_error(PARAMETER_PROBLEM, "pkd: you must specify a secret `--secret secret'");
  }
}

static void print(const struct ipt_ip* ip, const struct ipt_entry_match* match, int numeric) {
  struct ipt_pkd_info* info = (void *)match->data;
  
  printf("pkd: ");
  if(info->secret) {
    printf("secret: %s ", info->secret);
  }
  if (info->window) {
    printf("window: %lu ", info->window);
  }
  printf("\n");
}

static void save(const struct ipt_ip* ip, const struct ipt_entry_match* match) {
  struct ipt_pkd_info* info = (void *)match->data;

  if (info->secret) {
    printf("--secret %s ",info->secret);
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
