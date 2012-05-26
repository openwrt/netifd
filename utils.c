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
#include <string.h>
#include <stdlib.h>
#include "utils.h"

void
vlist_init(struct vlist_tree *tree, avl_tree_comp cmp, vlist_update_cb update)
{
	tree->update = update;
	tree->version = 1;

	avl_init(&tree->avl, cmp, 0, tree);
}

void
vlist_delete(struct vlist_tree *tree, struct vlist_node *node)
{
	if (!tree->no_delete)
		avl_delete(&tree->avl, &node->avl);
	tree->update(tree, NULL, node);
}

void
vlist_add(struct vlist_tree *tree, struct vlist_node *node, void *key)
{
	struct vlist_node *old_node = NULL;
	struct avl_node *anode;

	node->avl.key = key;
	node->version = tree->version;

	anode = avl_find(&tree->avl, key);
	if (anode) {
		old_node = container_of(anode, struct vlist_node, avl);
		if (tree->keep_old || tree->no_delete) {
			old_node->version = tree->version;
			goto update_only;
		}

		avl_delete(&tree->avl, anode);
	}

	avl_insert(&tree->avl, &node->avl);

update_only:
	tree->update(tree, node, old_node);
}

void
vlist_flush(struct vlist_tree *tree)
{
	struct vlist_node *node, *tmp;

	avl_for_each_element_safe(&tree->avl, node, avl, tmp) {
		if ((node->version == tree->version || node->version == -1) &&
		    tree->version != -1)
			continue;

		vlist_delete(tree, node);
	}
}

void
vlist_flush_all(struct vlist_tree *tree)
{
	tree->version = -1;
	vlist_flush(tree);
}


void
__vlist_simple_init(struct vlist_simple_tree *tree, int offset)
{
	INIT_LIST_HEAD(&tree->list);
	tree->version = 1;
	tree->head_offset = offset;
}

void
vlist_simple_delete(struct vlist_simple_tree *tree, struct vlist_simple_node *node)
{
	char *ptr;

	list_del(&node->list);
	ptr = (char *) node - tree->head_offset;
	free(ptr);
}

void
vlist_simple_flush(struct vlist_simple_tree *tree)
{
	struct vlist_simple_node *n, *tmp;

	list_for_each_entry_safe(n, tmp, &tree->list, list) {
		if ((n->version == tree->version || n->version == -1) &&
		    tree->version != -1)
			continue;

		vlist_simple_delete(tree, n);
	}
}

void
vlist_simple_replace(struct vlist_simple_tree *dest, struct vlist_simple_tree *old)
{
	struct vlist_simple_node *n, *tmp;

	vlist_simple_update(dest);
	list_for_each_entry_safe(n, tmp, &old->list, list) {
		list_del(&n->list);
		vlist_simple_add(dest, n);
	}
	vlist_simple_flush(dest);
}

void
vlist_simple_flush_all(struct vlist_simple_tree *tree)
{
	tree->version = -1;
	vlist_simple_flush(tree);
}
