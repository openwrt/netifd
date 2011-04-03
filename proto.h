#ifndef __NETIFD_PROTO_H
#define __NETIFD_PROTO_H

struct interface_proto_state;

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

struct interface_proto_state *get_default_proto(void);
int interface_proto_event(struct interface_proto_state *proto,
			  enum interface_proto_cmd cmd, bool force);

#endif
