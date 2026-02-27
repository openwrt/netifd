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
#ifndef __NETIFD_PROTO_UCODE_H
#define __NETIFD_PROTO_UCODE_H

#include <ucode/vm.h>

uc_value_t *uc_netifd_add_proto_fn(uc_vm_t *vm, size_t nargs);

#endif
