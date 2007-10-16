/*
 * Copyright (c) 2007 Eric Estabrooks <eric@urbanrage.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef _ipt_pkd_h_
#define _ipt_pkd_h_

#define PKD_SECRET_SIZE 40

struct ipt_pkd_info {
	char secret[PKD_SECRET_SIZE];
};

#endif
