/*
 * netifd - network interface daemon
 * Copyright (C) 2025 Felix Fietkau <nbd@nbd.name>
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

#ifndef __NETIFD_UCODE_H
#define __NETIFD_UCODE_H

#include <stdbool.h>

void netifd_ucode_config_load(bool start);
void netifd_ucode_check_network_enabled(void);
void netifd_ucode_hotplug_event(const char *name, bool add);
void netifd_ucode_init(void);
void netifd_ucode_free(void);

#endif
