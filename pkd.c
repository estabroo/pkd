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
#include <asm/semaphore.h>
#include <asm/atomic.h>
#include <linux/version.h>

#include "ipt_pkd.h"

MODULE_AUTHOR("Eric Estabrooks <eric@urbanrage.com>");
MODULE_DESCRIPTION("IP tables port knock detection");
MODULE_LICENSE("GPL");

#if 0
static void hexdump(unsigned char *buf, unsigned int len)
{
  while (len--) {
    printk("%02x", *buf++);
  }
  printk("\n");
}
#endif

#define _PKD_BUFFERS 4

struct _pkd_buff {
  struct semaphore    sem;
  struct crypto_hash* tfm;
  unsigned char*      sbuff;
};

static struct _pkd_buff pkd_buffers[_PKD_BUFFERS]; /* pointers to buffer used for scatterlist */
static char check[] = "PKD0";
static unsigned char _pkd_next_sem = 0;
static DEFINE_SPINLOCK(_pkd_lock);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static int
ipt_pkd_match(const struct sk_buff *skb,
              const struct net_device *in, const struct net_device *out,
              const struct xt_match *match, const void *matchinfo,
              int offset, unsigned int protoff, int *hotdrop)
#else
static bool
ipt_pkd_match(const struct sk_buff *skb,
              const struct net_device *in, const struct net_device *out,
              const struct xt_match *match, const void *matchinfo,
              int offset, unsigned int protoff, bool *hotdrop)
#endif

{
    struct iphdr*              iph;
    struct udphdr*             uh;
    struct udphdr              _udph;
    char*                      pdata;
    char                       result[64];
    struct scatterlist         sg[1];
    struct hash_desc           desc;
    int                        i;
    int                        err;
    unsigned short             len;
    struct timeval             current_time;
    time_t                     tpacket_time;
    time_t                     packet_time;
    unsigned char              wait_on_sem;
    unsigned long              pdiff;
    const struct ipt_pkd_info* info = matchinfo;

    if (skb == NULL) {
      printk(KERN_NOTICE "ipt_pkd: invalid skb info (NULL)\n"); 
      return 0;
    }
    if (info == NULL) {
      printk(KERN_NOTICE "ipt_pkd: invalid match info (NULL)\n"); 
      return 0;
    }
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
    iph = skb->nh.iph;
#else
    iph = ip_hdr(skb);
#endif
    if (iph == NULL) {
      return 0;
    }
    if (iph->protocol != IPPROTO_UDP) { /* just in case they didn't filter tcp out for us */
      return 0;
    }

    uh = skb_header_pointer(skb, protoff, sizeof(_udph), &_udph);
    if (uh == NULL) {
      printk(KERN_NOTICE "ipt_pkd: skb_header_pointer returned a NULL\n"); 
      return 0;
    }
#ifndef __BIG_ENDIAN
    len = __swab16(uh->len);
#else
	len = uh->len;
#endif
    if (len != 64) { /* knock packet is 64 bytes, 8 header, 4 id, 8 time, 12 random, 32 sha256 */
      return 0;
    }
    pdata = (void *)uh + 8;
    
    for (i=0; i < 4; i++) { /* quick check so we can bail out early if it isn't a knock */
      if (pdata[i] != check[i]) {
        return 0;
      }
    }

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
      printk(KERN_NOTICE "ipt_pkd: packet outside of time window, replay attack? %lu\n", pdiff); 
      return 0;
    }

    /* acquire a buffer to use, if none available wait */
    for (i=0; i < _PKD_BUFFERS; i++) {
      err = down_trylock(&pkd_buffers[i].sem);
      if (err == 0) break;
    }
    if (err != 0) {
      spin_lock_bh(&_pkd_lock);
      wait_on_sem = _pkd_next_sem;
      _pkd_next_sem = (_pkd_next_sem + 1) % _PKD_BUFFERS;
      spin_unlock_bh(&_pkd_lock);
      err = down_interruptible(&pkd_buffers[wait_on_sem].sem);
      while (err != 0) { /* need to check what kind of error? */
        err = down_interruptible(&pkd_buffers[wait_on_sem].sem);
      }
      i = wait_on_sem; /* point at the right buffer */
    }

    memset(&desc, 0, sizeof(desc)); /* probably don't need to do this */
    desc.tfm = pkd_buffers[i].tfm;
    desc.flags = 0;
    
    memcpy(pkd_buffers[i].sbuff, pdata, 24);
    memcpy(pkd_buffers[i].sbuff+24, info->key, PKD_KEY_SIZE);

    sg_set_buf(&sg[0], pkd_buffers[i].sbuff, 24+PKD_KEY_SIZE);

    err = crypto_hash_digest(&desc, sg, 24+PKD_KEY_SIZE, result);
    if (err) {
      printk(KERN_WARNING "ipt_pkd: digest sha256 failed, err = %d\n", err);
      up(&pkd_buffers[i].sem);
      return 0;
    }

    err = memcmp(result, &pdata[24], crypto_hash_digestsize(pkd_buffers[i].tfm));
    up(&pkd_buffers[i].sem);

    if (err == 0) {
      return 1;
    }
    return 0;
}

static struct xt_match pkd_match = {
	.name		= "pkd",
	.family		= AF_INET,
	.match		= ipt_pkd_match,
	.matchsize	= sizeof(struct ipt_pkd_info),
	.me		= THIS_MODULE,
};

static int __init ipt_pkd_init(void)
{
    int err;
    int i;
  
    _pkd_next_sem = 0;
    memset(pkd_buffers, 0, sizeof(pkd_buffers));
    for (i=0; i < _PKD_BUFFERS; i++) {
      sema_init(&pkd_buffers[i].sem, 1);
      pkd_buffers[i].tfm = crypto_alloc_hash("sha256", 0, CRYPTO_ALG_ASYNC);
      if (IS_ERR(pkd_buffers[i].tfm)) {
        printk("ipt_pkd: failed to load transform for sha256: %ld\n", PTR_ERR(pkd_buffers[i].tfm));
        for (--i; i >= 0; i--) {
          kfree(pkd_buffers[i].sbuff);
          pkd_buffers[i].sbuff = NULL;
          crypto_free_hash(pkd_buffers[i].tfm);
          pkd_buffers[i].tfm = NULL;
        }
        return -EAGAIN;
      }
      pkd_buffers[i].sbuff = kmalloc(24+PKD_KEY_SIZE, GFP_KERNEL);
      if (pkd_buffers[i].sbuff == NULL) {
        crypto_free_hash(pkd_buffers[i].tfm);
        pkd_buffers[i].tfm = NULL;
        for (--i; i >= 0; i--) {
          kfree(pkd_buffers[i].sbuff);
          pkd_buffers[i].sbuff = NULL;
          crypto_free_hash(pkd_buffers[i].tfm);
          pkd_buffers[i].tfm = NULL;
        }
        return -ENOMEM;
      }
    }
    err = xt_register_match(&pkd_match);
    return err;
}

static void __exit ipt_pkd_exit(void)
{
    int i;
    
    for (i=0; i < _PKD_BUFFERS; i++) {
      if (pkd_buffers[i].sbuff != NULL) {
        kfree(pkd_buffers[i].sbuff);
      }
      if (pkd_buffers[i].tfm != NULL) {
      	crypto_free_hash(pkd_buffers[i].tfm);
      }
    }
    xt_unregister_match(&pkd_match);
}

module_init(ipt_pkd_init);
module_exit(ipt_pkd_exit);
