#ifndef __NETIFD_PORT_SPLIT_H
#define __NETIFD_PORT_SPLIT_H

struct uci_context;
struct uci_package;

#ifdef DEVLINK_PORT_SPLIT
void port_split_config_init(struct uci_context *ctx, struct uci_package *pkg);
void port_split_shutdown(void);
#else
static inline void
port_split_config_init(struct uci_context *ctx, struct uci_package *pkg)
{
}

static inline void
port_split_shutdown(void)
{
}
#endif

#endif
