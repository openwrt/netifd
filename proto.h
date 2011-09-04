#ifndef __NETIFD_PROTO_H
#define __NETIFD_PROTO_H

struct interface;
struct interface_proto_state;
struct proto_handler;

enum interface_proto_event {
	IFPEV_UP,
	IFPEV_DOWN,
};

enum interface_proto_cmd {
	PROTO_CMD_SETUP,
	PROTO_CMD_TEARDOWN,
};

enum {
	PROTO_FLAG_IMMEDIATE = (1 << 0),
};

struct interface_proto_state {
	struct interface *iface;
	unsigned int flags;

	/* filled in by the protocol user */
	void (*proto_event)(struct interface_proto_state *, enum interface_proto_event ev);

	/* filled in by the protocol handler */
	int (*handler)(struct interface_proto_state *, enum interface_proto_cmd cmd, bool force);
	void (*free)(struct interface_proto_state *);
};


struct proto_handler {
	struct avl_node avl;

	const char *name;

	struct interface_proto_state *(*attach)(const struct proto_handler *h,
		struct interface *, struct uci_section *s);
};

void add_proto_handler(struct proto_handler *p);
void proto_init_interface(struct interface *iface, struct uci_section *s);
void proto_attach_interface(struct interface *iface, const char *proto_name);
int interface_proto_event(struct interface_proto_state *proto,
			  enum interface_proto_cmd cmd, bool force);

#endif
