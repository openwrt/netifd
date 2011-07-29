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
	const struct config_param_list *next;
	int n_params;
	const struct blobmsg_policy *params;
	const union config_param_info *info;
};

#endif
