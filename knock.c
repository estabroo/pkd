/*
 * Copyright (c) 2007  Eric Estabrooks <eric@urbanrage.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
  
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <netdb.h>
#include <termios.h>
#include <openssl/sha.h>

#include "ipt_pkd.h"

int setup_udp_socket(char* host, int port, char address[20]) {
  int                sfd;
  int                option_on = 1;
  int                error;
  char*              taddress;
  struct sockaddr_in saddr;
  struct hostent*    h_ent;
  
  h_ent = gethostbyname(host);
  if (h_ent->h_addrtype != AF_INET) {
    fprintf(stderr, "knock (ipt_pkd) currently only supports ipv4\n");
    exit(0);
  }
  memset(address, 0, 20);
  taddress = inet_ntoa(*((struct in_addr*)h_ent->h_addr_list[0]));
  strncpy(address, taddress, 19);

  fprintf(stderr, "address = [%s], port[%d]\n", address, port);
  sfd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sfd < 0) {
    perror("knock (ipt_pkd) Couldn't open a socket");
    exit(0);
  }
  
  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&option_on,
             sizeof(option_on));
  
  /* set up source sock_addr structure */
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = INADDR_ANY;
  saddr.sin_port = htons(port);
  
  error = bind(sfd, (struct sockaddr*)&saddr, sizeof(saddr));
  if (error < 0) {
    perror("knock couldn't bind socket to address");
    close(sfd);
    exit(0);
  }
  
  return sfd;
}

void usage(char* argv[]) {
  fprintf(stderr, "usage: %s [-o] host_to_knock [tag [port]]\n", argv[0]);
  fprintf(stderr, " -o use old packet format (pre 1.0 pkd installs)\n");
  exit(0);
}

#define hex(a) ((a) >= 'a' ? ((a) - 'a' + 10) : ((a) - '0'))

int main (int argc, char* argv[]) {
   int                sfd;
   int                fd;
   int                old; /* old style format? */
   unsigned short     port;
   unsigned char      hport[4];
   int                err;
   int                i,j;
   struct timeval     current_time;
   struct termios     term;
   char*              ptr;
   char               tkey[PKD_KEY_SIZE*2+3];
   char               key[PKD_KEY_SIZE];
   char               tag[PKD_TAG_SIZE];
   unsigned char      h;
   unsigned char      packet[68];
   unsigned char      randbits[12];
   SHA256_CTX         sha_c;
   unsigned char      md[SHA256_DIGEST_LENGTH];
   char               address[20];
   struct sockaddr_in saddr;

   if (strcmp(argv[1], "-o") == 0) {
     old = 1;
   } else {
     old = 0;
   }

   if ((argc < (2+old)) || (argc > (4+old))) {
     usage(argv);
   }
   
   
   /* get key */
   memset(&term, 0, sizeof(term));
   err = tcgetattr(fileno(stdin), &term);
   if (err != 0) {
     perror("Couldn't get terminal attributes");
     exit(0);
   }
   term.c_lflag &= ~ECHO;
   err = tcsetattr(fileno(stdin), TCSANOW, &term);
   if (err != 0) {
     perror("Couldn't set terminal attributes");
     exit(0);
   }
   memset(tkey, 0, sizeof(tkey));
   fprintf(stderr, "key: ");
   ptr = fgets(tkey, PKD_KEY_SIZE*2+3, stdin);
   fprintf(stderr, "\n");
   term.c_lflag |= ECHO;
   err = tcsetattr(fileno(stdin), TCSANOW, &term);

   if (tkey[strlen(tkey)-1] = '\n') {
     tkey[strlen(tkey)-1] = '\0';
   }
   memset(key, 0, sizeof(key));
   if (tkey[0] == '0' && tkey[1] == 'x') { /* entered in as hex, convert it */
     for(i=2,j=0; j < PKD_KEY_SIZE; i++,j++) {
       if (!isxdigit(tkey[i])) break;
       h = hex(tolower(tkey[i])) << 4;
       if (!isxdigit(tkey[++i])) {
         key[j++] = h;
         break;
       }
       h |= hex(tolower(ptr[i]));
       key[j] = h;
     }
   } else {
     strncpy(key, tkey, PKD_KEY_SIZE);
   }
   /*
   fprintf(stderr, "key: 0x");
   for(i=0; i < PKD_KEY_SIZE; i++) {
     fprintf(stderr, "%02x", key[i]);
   }
   fprintf(stderr, "\n");
   */
   
   /* get some random bits */
   fd = open("/dev/urandom", O_RDONLY);
   if (fd >= 0) {
     read(fd, randbits, 12);
     close(fd);
   } else {
     for (i=0; i < 12; i++) {
       randbits[i] = random() % 256;
     }
   }

   if (argc < (3+old)) {
     strncpy(tag, "PKD0", 4);
   } else {
     memset(tag, 0, sizeof(tag));
     ptr = argv[2+old];
     if (ptr[0] == '0' && ptr[1] == 'x') { /* entered in as hex, convert it */
       for(i=2,j=0; j < PKD_TAG_SIZE; i++,j++) {
         if (!isxdigit(ptr[i])) break;
         h = hex(tolower(ptr[i])) << 4;
         if (!isxdigit(ptr[++i])) {
           key[j++] = h;
           break;
         }
         h |= hex(tolower(ptr[i]));
         key[j] = h;
       }
     } else {
       strncpy(tag, ptr, PKD_TAG_SIZE);
     }
   }

   if (argc == (4+old)) {
     port = atoi(argv[3+old]);
   } else {
     port = randbits[3] << 8 | randbits[7];
   }
   if (port < 1024) {
     port += 1024;
   } else if (port > 50000) {
     port = 50000;
   }
   hport[0] = hport[2] = (port >> 8) & 0xff;
   hport[1] = hport[3] = port & 0xff;

   /* get ready to make the packet */
   err = SHA256_Init(&sha_c);
   if (err == 0) {
     fprintf(stderr, "SHA256_Init failed %d\n", err);
     exit(0);
   }

   memset(packet, 0, sizeof(packet));
   memcpy(packet, hport, 4);
   memcpy(packet+4, tag, 4);
   err = gettimeofday(&current_time, NULL);
   ptr = (void*)&current_time.tv_sec;

   for (i=0; i < sizeof(time_t); i++) {
#if __BYTE_ORDER == __BIG_ENDIAN
     packet[8+i] = ptr[sizeof(time_t) - i -1];
#else
     packet[8+i] = ptr[i];
#endif
   }

   /* add some pseudo randomness */
   for (i=0; i < 12; i++) {
     packet[16+i] = randbits[i];
   }

   memcpy(&packet[28], key, PKD_KEY_SIZE);
#if 0
   for (i=0; i < 28+PKD_KEY_SIZE; i++) {
     fprintf(stderr, "%02x", packet[i]);
   }
   fprintf(stderr, "\n");
#endif
   /* do the hash */
   if (old == 0) {
     err = SHA256_Update(&sha_c, packet, 68);
   } else {
     err = SHA256_Update(&sha_c, packet+4, 64);
   }
   if (err == 0) {
     fprintf(stderr, "SHA256_Update failed %d\n", err);
     exit(0);
   }
   err = SHA256_Final(md, &sha_c);
   if (err == 0) {
     fprintf(stderr, "SHA256_Final failed\n");
     exit(0);
   }

   /* copy hash results to the packet */
   for (i=0; i < SHA256_DIGEST_LENGTH; i++) {
     packet[28+i] = md[i];
   }

   /* set up socket */
   sfd = setup_udp_socket(argv[1+old], port, address);

   /* set up destination sock_addr structure */
   memset(&saddr, 0, sizeof(saddr));
   saddr.sin_family = AF_INET;
   saddr.sin_addr.s_addr = inet_addr(address);
   saddr.sin_port = htons(port);

   /* send the packet */
   sendto(sfd, packet+4, 24+SHA256_DIGEST_LENGTH, 0, (const struct sockaddr*)&saddr, sizeof(saddr));
   close(sfd);
   exit(0);
}

