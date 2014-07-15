/*
 * Copyright (c) 2007,2008 Eric Estabrooks <eric@urbanrage.com>
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

#ifdef LIBXTABLES
	#define PKD_ERROR xtables_error
#else
	#define PKD_ERROR exit_error
#endif

static struct option opts[] = {
	{ .name = "key",      .has_arg = 1, .flag = 0, .val = 'k' },
    { .name = "window",   .has_arg = 1, .flag = 0, .val = 'w' },
    { .name = "tag",      .has_arg = 1, .flag = 0, .val = 't' },
	{ .name = 0,          .has_arg = 0, .flag = 0, .val = 0   }
};

static void help(void) {
  printf("pkd v%s options:\n" 
         "    --key key      up to %d byte shared key. use 0x to indicate the key in hex,\n"
         "                   for example --key 0xab03be805172 or --key test.\n"
         "    --window time  window in seconds +- in which the packet can arrive.\n"
         "                   defaults to 10 giving a 20 second window.\n"
		 "                   use 0 to skip time check.\n"
         "   --tag tag       4 character tag, use different tags for different keys to\n"
         "                   speed up processing, default tag is PKD0.  The tag is\n"
         "                   checked before processing the packet allowing for early\n"
         "                   elimination when the knock packet is for a different key.\n"
         "                   use 0x to indicate the tag in hex (like --key).\n",
         PKD_VERSION, PKD_KEY_SIZE);
}


#ifdef IPT14
static void init(struct ipt_entry_match* match)
#else
static void init(struct ipt_entry_match* match, unsigned int* nfcache)
#endif
{
  struct ipt_pkd_info* info = (void *)(match)->data;

  memset(info->key, 0, sizeof(PKD_KEY_SIZE));
  strncpy(info->key, "AbC123kajsdf987nacva", PKD_KEY_SIZE);
  info->window = 10;
  strncpy(info->tag, "PKD0", PKD_TAG_SIZE); /* it's okay to not be null terminated */
}

#define hex(a) ((a) >= 'a' ? ((a) - 'a' + 10) : ((a) - '0'))

#ifdef IPT14
static int parse(int c, char** argv, int invert, unsigned int* flags, const void* entry,
                 struct ipt_entry_match** match)
#else
static int parse(int c, char** argv, int invert, unsigned int* flags, const struct ipt_entry* entry,
                 unsigned int* nfcache, struct ipt_entry_match** match)
#endif
{
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
      strncpy(info->key, optarg, PKD_KEY_SIZE); /* it's okay if the key isn't null terminated */
    }
    *flags |= 1;
    ret = 1;
  }; break;
  case 'w' : {
    info->window = atoi(optarg);
    *flags |= 2;
    ret = 1;
  }; break;
  case 't' : {
    memset(info->tag, 0, PKD_TAG_SIZE);
    if (optarg[0] == '0' && optarg[1] == 'x') {
      for (i=2,j=0; i < PKD_TAG_SIZE*2+2; i++,j++) {
        if (!isxdigit(optarg[i])) break;
        h = hex(tolower(optarg[i])) << 4;
        if (!isxdigit(optarg[++i])) { /* no lower nibble, make it a 0 */
          info->tag[j++] = h;
          break;
        }
        h |= hex(tolower(optarg[i]));
        info->tag[j] = h;
      }
    } else {
      strncpy(info->tag, optarg, PKD_TAG_SIZE); /* it's okay if the tag isn't null terminated */
    }
    *flags |= 4;
    ret = 1;
  }; break;
  default: ret = 0;
  };

  return ret;
}

static void final_check(unsigned int flags)
{
  //printf("flags = 0x%08x\n", flags);
  if ((flags & 1) == 0) {
    PKD_ERROR(PARAMETER_PROBLEM, "pkd: you must specify a key `--key key'");
  }
}

#ifdef IPT14
static void print(const void* ip, const struct ipt_entry_match* match, int numeric)
#else
static void print(const struct ipt_ip* ip, const struct ipt_entry_match* match, int numeric)
#endif
{
  struct ipt_pkd_info* info = (void *)match->data;
  int i;

  printf("pkd: ");
  if (info != NULL) {
    printf("key: 0x");
    for (i=0; i < PKD_KEY_SIZE; i++) {
      printf("%02x", info->key[i]);
    }
  
    printf(" window: %u", info->window);
    printf(" tag: 0x");
    for (i=0; i < PKD_TAG_SIZE; i++) {
      printf("%02x", info->tag[i]);
    }
    printf(" ");
  }
}

#ifdef IPT14
static void save(const void* ip, const struct ipt_entry_match* match)
#else
static void save(const struct ipt_ip* ip, const struct ipt_entry_match* match)
#endif
{
  struct ipt_pkd_info* info = (void *)match->data;
  int                  i;

  if (info != NULL) {
    printf(" --key 0x");
    for (i=0; i < PKD_KEY_SIZE; i++) {
      printf("%02x", info->key[i]);
    }
    printf(" --window %u", info->window);
    printf(" --tag 0x");
    for (i=0; i < PKD_TAG_SIZE; i++) {
      printf("%02x", info->tag[i]);
    }
    printf(" ");
  }
}

#ifdef XTABLES
static struct xtables_match pkd = { 
    .name          = "pkd",
#ifdef LIBXTABLES
    .version       = XTABLES_VERSION, 
#else
    .version       = IPTABLES_VERSION, 
#endif
    .family        = PF_INET,
    .size          = XT_ALIGN(sizeof(struct ipt_pkd_info)),
    .userspacesize = XT_ALIGN(sizeof(struct ipt_pkd_info)),
    .help          = help,
    .init          = init,
    .parse         = parse,
    .final_check   = final_check,
    .print         = print,
    .save          = save,
    .extra_opts    = opts
};
#else
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
#endif

void _init(void) {
#ifdef XTABLES
    xtables_register_match(&pkd);
#else
	register_match(&pkd);
#endif
}
