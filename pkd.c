/*
 * Copyright (c) 2007 Eric Estabrooks <eric@urbanrage.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <linux/init.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/random.h>
#include <linux/bitops.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/netfilter/x_tables.h>
#include <asm/byteorder.h>

#include "ipt_pkd.h"

MODULE_AUTHOR("Eric Estabrooks <eric@urbanrage.com>");
MODULE_DESCRIPTION("IP tables port knock detection");
MODULE_LICENSE("GPL");

static char check[] = "PKD0";

static int
ipt_pkd_match(const struct sk_buff *skb,
              const struct net_device *in, const struct net_device *out,
              const struct xt_match *match, const void *matchinfo,
              int offset, unsigned int protoff, int *hotdrop)
{
    const struct ipt_pkd_info* info = matchinfo;
    struct iphdr*       iph;
    struct udphdr*      uh;
    char*               pdata;
    char                result[64];
    struct scatterlist  sg[2];
    struct crypto_hash* tfm;
    struct hash_desc    desc;
    int                 i;
    int                 err;
    int                 ret = 0;
    struct timeval      current_time;
    time_t              packet_time;
    unsigned long       pdiff;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP) { /* just in case they didn't filter tcp out for us */
      return 0;
    }
    uh = udp_hdr(skb);
    if (uh->len != 64) { /* pkd is 64 bytes */
      return 0;
    }
    pdata = (void *)uh + 8;
    
    for (i=0; i < 4; i++) {
      if (pdata[i] != check[i]) {
        return 0;
      }
    }

    printk("ipt_pkd: detected a port knock, checking validity\n");

    /* check time interval */
    do_gettimeofday(&current_time);
    packet_time = 0;
    memcpy(&packet_time, &pdata[4], sizeof(time_t));
#ifdef __BIG_ENDIAN
    if (sizeof(time_t) == 4) {
      __swab32(__le32(packet_time));
    } else {
      __swab64(__le64(packet_time));
    }
#endif

    pdiff = abs(current_time.tv_sec - packet_time);
    if (pdiff > info->window) { /* packet outside of time window */
      printk("ipt_pkd: packet outside of time window, replay attack?\n");
      return 0;
    }

    tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
      printk("ipt_pkd: failed to load transform for sha256: %ld\n", PTR_ERR(tfm));
      return 0;
    }
    desc.tfm = tfm;
    desc.flags = 0;

    sg_set_buf(&sg[0], pdata, 24);
    sg_set_buf(&sg[1], info->secret, PKD_SECRET_SIZE);

    err = crypto_hash_digest(&desc, sg, 24+PKD_SECRET_SIZE, result);
    if (err) {
      printk("ipt_pkd: digest sha256 failed, err = %d\n", err);
      crypto_free_hash(tfm);
      return 0;
    }
    
    ret = memcmp(result, &pdata[32], crypto_hash_digestsize(tfm));
    crypto_free_hash(tfm);

    return (!ret);
}

static int
ipt_pkd_checkentry(const char *tablename, const void *ip,
                   const struct xt_match *match, void *matchinfo,
                   unsigned int hook_mask)
{
    struct ipt_pkd_info* info = matchinfo;
    
    if (info->secret[0] == '\0' || strnlen(info->secret, PKD_SECRET_SIZE) == PKD_SECRET_SIZE) {
      return 0;
    }
	return 1;
}

static struct xt_match pkd_match = {
	.name		= "pkd",
	.family		= AF_INET,
	.match		= ipt_pkd_match,
	.matchsize	= sizeof(struct ipt_pkd_info),
	.checkentry	= ipt_pkd_checkentry,
	.me		= THIS_MODULE,
};

static int __init ipt_pkd_init(void)
{
	int err;

	err = xt_register_match(&pkd_match);
	return err;
}

static void __exit ipt_pkd_exit(void)
{
	xt_unregister_match(&pkd_match);
}

module_init(ipt_pkd_init);
module_exit(ipt_pkd_exit);
