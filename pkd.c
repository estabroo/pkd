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

static void hexdump(unsigned char *buf, unsigned int len)
{
        while (len--)
                printk("%02x", *buf++);

        printk("\n");
}


static char check[] = "PKD0";

static int
ipt_pkd_match(const struct sk_buff *skb,
              const struct net_device *in, const struct net_device *out,
              const struct xt_match *match, const void *matchinfo,
              int offset, unsigned int protoff, int *hotdrop)
{
    struct iphdr*              iph;
    struct udphdr*             uh;
    struct udphdr              _udph;
    char*                      sbuff; /* buffer for scatter */
    char*                      pdata;
    char                       result[64];
    struct scatterlist         sg[1];
    struct crypto_hash*        tfm;
    struct hash_desc           desc;
    int                        i;
    int                        err;
    int                        ret = 0;
    unsigned short             len;
    struct timeval             current_time;
    time_t                     tpacket_time;
    time_t                     packet_time;
    unsigned long              pdiff;
    const struct ipt_pkd_info* info = matchinfo;

    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_UDP) { /* just in case they didn't filter tcp out for us */
      printk("ipt_pkd: proto not udp\n");
      return 0;
    }
    uh = skb_header_pointer(skb, protoff, sizeof(_udph), &_udph);
#ifndef __BIG_ENDIAN
    len = __swab16(uh->len);
#endif
    if (len != 64) { /* pkd is 64 bytes */
      //printk("ipt_pkd: wrong packet size: %d != 64, [%d][%d]\n", len, __swab16(uh->source), __swab16(uh->dest));
      return 0;
    }
    pdata = (void *)uh + 8;
    
    for (i=0; i < 4; i++) {
      if (pdata[i] != check[i]) {
        //printk("ipt_pkd: header check failed: %d 0x%02x 0x%02x\n", i, pdata[i], check[i]);
        return 0;
      }
    }

    printk("ipt_pkd: detected a port knock, checking validity\n");

    /* check time interval */
    do_gettimeofday(&current_time);
    packet_time = 0;
    memcpy(&tpacket_time, &pdata[4], sizeof(time_t));
#ifdef __BIG_ENDIAN
    if (sizeof(time_t) == 4) {
     packet_time =  __swab32((__le32)tpacket_time);
    } else {
      packet_time = __swab64((__le64)tpacket_time);
    }
#else
    packet_time = tpacket_time;
#endif

    pdiff = abs(current_time.tv_sec - packet_time);
    if (pdiff > info->window) { /* packet outside of time window */
      printk("ipt_pkd: packet outside of time window, replay attack? %lu\n", pdiff); 
      return 0;
    }
    
    sbuff = kmalloc(64, GFP_KERNEL); /* slab this? or make a spinloc on a static buffer */
    if (sbuff == NULL) {
      printk("ipt_pkd: couldn't allocate memory\n");
      return 0;
    }

    tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
    if (IS_ERR(tfm)) {
      printk("ipt_pkd: failed to load transform for sha256: %ld\n", PTR_ERR(tfm));
      kfree(sbuff);
      return 0;
    }

    desc.tfm = tfm;
    desc.flags = 0;
    
    memcpy(sbuff, pdata, 24);
    memcpy(sbuff+24, info->secret, PKD_SECRET_SIZE);

    sg_set_buf(&sg[0], sbuff, 24+PKD_SECRET_SIZE);

    printk("ipt_pkd: about to hash\n");

    err = crypto_hash_digest(&desc, sg, 24+PKD_SECRET_SIZE, result);
    if (err) {
      printk("ipt_pkd: digest sha256 failed, err = %d\n", err);
      kfree(sbuff);
      crypto_free_hash(tfm);
      return 0;
    }

    ret = memcmp(result, &pdata[24], crypto_hash_digestsize(tfm));
    kfree(sbuff);
    crypto_free_hash(tfm);
    
    printk("ipt_pkd: memcmp result %d\n", ret);
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
