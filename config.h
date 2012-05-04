/*
 * netifd - network interface daemon
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef __NETIFD_CONFIG_H
#define __NETIFD_CONFIG_H

#include <libubox/blobmsg.h>

extern bool config_init;

enum config_param_type {
	CONFIG_PARAM_TYPE_SIMPLE,
	CONFIG_PARAM_TYPE_LIST,
	CONFIG_PARAM_TYPE_SECTION,
};

union config_param_info {
	enum blobmsg_type type;
	struct config_params *section;
};

struct config_param_list {
	int n_params, n_next;

	const struct blobmsg_policy *params;
	const union config_param_info *info;

	const struct config_param_list *next[];
};

#ifndef BITS_PER_LONG
#define BITS_PER_LONG (8 * sizeof(unsigned long))
#endif

static inline void set_bit(unsigned long *bits, int bit)
{
	bits[bit / BITS_PER_LONG] |= (1UL << (bit % BITS_PER_LONG));
}

static inline bool test_bit(unsigned long *bits, int bit)
{
	return !!(bits[bit / BITS_PER_LONG] & (1UL << (bit % BITS_PER_LONG)));
}

void config_init_all(void);
bool config_check_equal(struct blob_attr *c1, struct blob_attr *c2,
			const struct config_param_list *config);
bool config_diff(struct blob_attr **tb1, struct blob_attr **tb2,
		 const struct config_param_list *config, unsigned long *diff);

struct blob_attr *config_memdup(struct blob_attr *attr);

#endif
