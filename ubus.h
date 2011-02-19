#ifndef __NETIFD_UBUS_H
#define __NETIFD_UBUS_H

int netifd_ubus_init(const char *path);
void netifd_ubus_done(void);
void netifd_ubus_add_interface(struct interface *iface);
void netifd_ubus_remove_interface(struct interface *iface);

#endif
