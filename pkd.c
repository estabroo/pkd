/*
 * Copyright (c) 2007,2008 Eric Estabrooks <eric@urbanrage.com>
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
#include <linux/proc_fs.h>
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
#include <net/net_namespace.h>
#endif
#include "ipt_pkd.h"

#ifndef PKD_VERSION
#define PKD_VERSION "unknown"
#endif

MODULE_AUTHOR("Eric Estabrooks <eric@urbanrage.com>");
MODULE_DESCRIPTION("iptables port knock detection using spa");
MODULE_VERSION(PKD_VERSION);
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
#define _PKD_PACKETS 32

struct _pkd_buff {
  struct semaphore    sem;
  struct crypto_hash* tfm;
  unsigned char*      sbuff;
};

struct _pkd_packets {
  unsigned long replays; /* number of times we've seen this packet */
  unsigned char dport[2]; /* destination port */
  unsigned char packet[56]; /* packet */
  time_t        last_seen; /* for age/hits check */
};

static struct _pkd_packets pkd_packets[_PKD_PACKETS]; /* old good packets, help cut down on replay */
static int pkd_phead; /* next potential replacement candidate */
static struct _pkd_buff pkd_buffers[_PKD_BUFFERS]; /* pointers to buffer used for scatterlist */
//static char check[] = "PKD0"; // now handled by --tag option
static unsigned long _pkd_replay_count;
static unsigned long _pkd_good_count;
static unsigned long _pkd_ootime_count;
static unsigned char _pkd_next_sem = 0;
static DEFINE_SPINLOCK(_pkd_lock);
static DEFINE_SPINLOCK(_pkd_pkt_lock);

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *proc_entry;
#endif

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
    int                        i,j;
    int                        err;
    unsigned long              tleast;
    unsigned short             len;
    unsigned char*             dport;
    struct timeval             current_time;
    time_t                     tpacket_time;
    time_t                     packet_time;
    unsigned char              wait_on_sem;
    unsigned long              pdiff;
    const struct ipt_pkd_info* info = matchinfo;
    
    /* do early kickout/fatal checks */
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
    dport = (unsigned char*)uh+2;

    for (i=0; i < 4; i++) { /* quick check so we can bail out early if it isn't a knock or for a different knock */
      if (pdata[i] != info->tag[i]) {
        return 0;
      }
    }

    /* check time interval, skip check if user set window to 0 */
    do_gettimeofday(&current_time);
    if (info->window > 0) {      
      packet_time = 0;
      memcpy(&tpacket_time, &pdata[4], sizeof(time_t));
#ifdef __BIG_ENDIAN
      if (sizeof(time_t) == 8) {
        packet_time = __swab64((__le64)tpacket_time);
      } else {
        packet_time =  __swab32((__le32)tpacket_time);
      }
#else
      packet_time = tpacket_time;
#endif
      pdiff = abs(current_time.tv_sec - packet_time);
      if (pdiff > info->window) { /* packet outside of time window */
        /*printk(KERN_NOTICE "ipt_pkd: packet outside of time window, replay attack? %lu\n", pdiff);*/
        _pkd_ootime_count++;
        return 0;
      }
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

    memcpy(pkd_buffers[i].sbuff, dport, 2);
    memcpy(pkd_buffers[i].sbuff+2, dport, 2); /* lazy fix so we don't have to change the userspace as well */
    memcpy(pkd_buffers[i].sbuff+4, pdata, 24);
    memcpy(pkd_buffers[i].sbuff+28, info->key, PKD_KEY_SIZE);

    sg_set_buf(&sg[0], pkd_buffers[i].sbuff, 28+PKD_KEY_SIZE);

    err = crypto_hash_digest(&desc, sg, 28+PKD_KEY_SIZE, result);
    if (err) {
      printk(KERN_WARNING "ipt_pkd: digest sha256 failed, err = %d\n", err);
      up(&pkd_buffers[i].sem);
      return 0;
    }
    err = memcmp(result, &pdata[24], crypto_hash_digestsize(pkd_buffers[i].tfm));
    up(&pkd_buffers[i].sem);
    

    if (err == 0) {
      spin_lock(&_pkd_pkt_lock);      /* good knock, put on list to reduce replay? */
      packet_time = 0;
      j = pkd_phead;
      for (i=0; i < _PKD_PACKETS; i++) {
        tleast = pkd_packets[i].replays;
        if (tleast >= 1) {
          pdiff = (current_time.tv_sec - pkd_packets[i].last_seen);
          tpacket_time = pdiff/tleast;
          if (tpacket_time > packet_time) {
            packet_time = tpacket_time;
            j = i;
          }
          err = memcmp(dport, pkd_packets[i].dport, 2);
          if (err != 0) { /* not a match, skip the rest of the check */
            continue;
          }
          err = memcmp(pdata, pkd_packets[i].packet, 56);
          if (err == 0) {
            _pkd_replay_count++;
            tleast++;
            if (tleast == 0) {
              /* wow, someone rolled over the replay (thats about 6 hours of continuous packet
                 sending at 100mb/s if this is a 32bit system and about 3 million years on 64bit) */
              tleast = 1000; /* keep it and start it at a decent number */
            }
            pkd_packets[i].replays = tleast;
            pkd_packets[i].last_seen = current_time.tv_sec;
            spin_unlock(&_pkd_pkt_lock);
            /*printk(KERN_WARNING "ipt_pkd: possible replay attack, packet repeated [%u]\n", tleast);*/
            return 0;
          }
          /* if the packet time is outside the window check
             then we can remove them here since the time
             check will kick the packets out before this point */
          if ((info->window > 0) && (pdiff > (2*info->window))) {
            pkd_packets[i].replays = 0;
          }
        }
      }
      /* didn't find a match add it to list */
      if (pkd_packets[pkd_phead].replays == 0) { /* unused */
        i = pkd_phead;
      } else {
        i = j;
      }
      memcpy(pkd_packets[i].dport, dport, 2);
      memcpy(pkd_packets[i].packet, pdata, 56);
      pkd_packets[i].last_seen = current_time.tv_sec;
      pkd_packets[i].replays = 1;
      pkd_phead = (pkd_phead + 1) % _PKD_PACKETS;
      spin_unlock(&_pkd_pkt_lock);
      _pkd_good_count++;
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

static int proc_pkd_read(char* page, char** start, off_t off,
                         int count, int *eof, void *data) {
  int len;
  int i,j;
  unsigned short port;
  char buffer[4096];

  /* number of bytes to return with each read */
  spin_lock(&_pkd_pkt_lock);
  len = snprintf(buffer, sizeof(buffer), "Packets outside of time window: %lu\n", _pkd_ootime_count);
  i = snprintf(buffer+len, sizeof(buffer)-len, "Good packets: %lu\n", _pkd_good_count);
  len += i;
  i = snprintf(buffer+len, sizeof(buffer)-len, "Replayed packets: %lu\n", _pkd_replay_count);
  len += i;
  for (j=0; j < _PKD_PACKETS; j++) {
    if (pkd_packets[j].replays > 1) {
      port = (pkd_packets[j].dport[0] << 8) | pkd_packets[j].dport[1];
      i = snprintf(buffer+len, sizeof(buffer)-len, "  port %5d seen %lu, last %lu\n", port, pkd_packets[j].replays,
                   pkd_packets[j].last_seen);
      len += i;
      if (len >= sizeof(buffer)) {
        len = sizeof(buffer);
        buffer[sizeof(buffer)-1] = '\0';
        break;
      }
    }
  }
  spin_unlock(&_pkd_pkt_lock);
  if (off >= len) {
    *eof = 1;
    len = 0;
    *start = NULL;
  } else {
    i = count;
    if ((i+off) > len) {
      i = len - off;
      *eof = 1;
    }
    memcpy(page, buffer+off, i);
    len = i;
    *start = page;
  }

  return len;
}

static int __init ipt_pkd_init(void)
{
    int err;
    int i;

    _pkd_next_sem = 0;
    _pkd_replay_count = 0;
    _pkd_good_count = 0;
    _pkd_ootime_count = 0;
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
      pkd_buffers[i].sbuff = kmalloc(28+PKD_KEY_SIZE, GFP_KERNEL);
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

    memset(pkd_packets, 0, sizeof(pkd_packets));
    spin_lock_init(&_pkd_lock);
    spin_lock_init(&_pkd_pkt_lock);
    pkd_phead = 0;

    err = xt_register_match(&pkd_match);
#ifdef CONFIG_PROC_FS
    if (err) {
      return err;
    }
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
    proc_entry = create_proc_read_entry("ipt_pkd", 0400, init_net.proc_net, proc_pkd_read, NULL);
#else
    proc_entry = create_proc_read_entry("ipt_pkd", 0400, proc_net, proc_pkd_read, NULL);
#endif
    if (proc_entry == NULL) {
      xt_unregister_match(&pkd_match);
      err = -ENOMEM;
    }
#endif
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
#ifdef CONFIG_PROC_FS
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,23))
    remove_proc_entry("ipt_pkd", init_net.proc_net);
#else
    remove_proc_entry("ipt_pkd", proc_net);
#endif
#endif
    xt_unregister_match(&pkd_match);
}

module_init(ipt_pkd_init);
module_exit(ipt_pkd_exit);
