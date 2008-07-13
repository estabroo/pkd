/*
 * Copyright (c) 2007,2008 Eric Estabrooks <eric@urbanrage.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef _ipt_pkd_h_
#define _ipt_pkd_h_

#define PKD_KEY_SIZE 40
#define PKD_TAG_SIZE 4

struct ipt_pkd_info {
  unsigned char key[PKD_KEY_SIZE];
  unsigned char tag[PKD_TAG_SIZE];
  unsigned int  window;
};

#endif
