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

int setup_udp_socket(char* host, int port) {
  int                sfd;
  int                option_on = 1;
  int                error;
  char*              taddress;
  char               address[20];
  struct sockaddr_in saddr;
  struct hostent*    h_ent;
  
  h_ent = gethostbyname(host);
  if (h_ent->h_addrtype != AF_INET) {
    fprintf(stderr, "knock (ipt_pkd) currently only supports ipv4\n");
    exit(0);
  }
  memset(address, 0, sizeof(address));
  taddress = inet_ntoa(*((struct in_addr*)h_ent->h_addr_list[0]));
  strncpy(address, taddress, sizeof(address)-1);

  fprintf(stderr, "address = [%s], port[%d]\n", address, port);
  sfd = socket(PF_INET, SOCK_DGRAM, 0);
  if (sfd < 0) {
    perror("knock (ipt_pkd) Couldn't open a socket");
    exit(0);
  }
  
  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&option_on,
             sizeof(option_on));
  
  /* set up sock_addr structure */
  memset(&saddr, 0, sizeof(saddr));
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = inet_addr(address);
  saddr.sin_port = htons(port);
  
  error = connect(sfd, (struct sockaddr*)&saddr, sizeof(saddr));
  if (error < 0) {
    perror("knock couldn't connect socket to address");
    close(sfd);
    exit(0);
  }
  
  return sfd;
}

void usage(char* argv[]) {
  fprintf(stderr, "usage: %s host_to_knock [port]\n", argv[0]);
  exit(0);
}

int main (int argc, char* argv[]) {
   int                sfd;
   int                fd;
   int                port;
   int                err;
   int                i;
   struct timeval     current_time;
   struct termios     term;
   char*              ptr;
   char               secret[PKD_SECRET_SIZE+1];
   unsigned char      packet[64];
   unsigned char      randbits[12];
   SHA256_CTX         sha_c;
   unsigned char      md[SHA256_DIGEST_LENGTH];

   if ((argc < 2) || (argc > 3)) {
     usage(argv);
   }
   
   /* get secret */
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
   memset(secret, 0, sizeof(secret));
   fprintf(stderr, "secret: ");
   ptr = fgets(secret, PKD_SECRET_SIZE+1, stdin);
   fprintf(stderr, "\n");
   term.c_lflag |= ECHO;
   err = tcsetattr(fileno(stdin), TCSANOW, &term);

   if (secret[strlen(secret)-1] = '\n') {
   	secret[strlen(secret)-1] = '\0';
   }
   fprintf(stderr, "secret[%s]\n", secret);

   sfd = setup_udp_socket(argv[1], port);


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

   if (argc == 3) {
     port = atoi(argv[2]);
   } else {
     port = randbits[3] << 8 | randbits[7];
   }
   if (port < 1024) {
     port += 1024;
   }

   /* get ready to make the packet */
   err = SHA256_Init(&sha_c);
   if (err == 0) {
     fprintf(stderr, "SHA256_Init failed %d\n", err);
     exit(0);
   }

   memset(packet, 0, sizeof(packet));
   strcpy(packet, "PKD0");
   err = gettimeofday(&current_time, NULL);
   ptr = (void*)&current_time.tv_sec;

   for (i=0; i < sizeof(time_t); i++) {
#if __BYTE_ORDER == __BIG_ENDIAN
     packet[4+i] = ptr[sizeof(time_t) - i -1];
#else
     packet[4+i] = ptr[i];
#endif
   }

   /* add some pseudo randomness */
   for (i=0; i < 12; i++) {
     packet[12+i] = randbits[i];
   }

   memcpy(&packet[24], secret, PKD_SECRET_SIZE);

   /* do the hash */
   err = SHA256_Update(&sha_c, packet, 64);
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
     packet[24+i] = md[i];
   }

   /* send the packet */
   write(sfd, packet, 24+SHA256_DIGEST_LENGTH);
   close(sfd);
   exit(0);
}

