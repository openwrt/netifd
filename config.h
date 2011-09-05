#ifndef __NETIFD_CONFIG_H
#define __NETIFD_CONFIG_H

#include <libubox/blobmsg.h>

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

struct config_state {
	struct blob_attr *data;
	unsigned int version;
};

void config_set_state(struct config_state *state, struct blob_attr *attr);


#endif
