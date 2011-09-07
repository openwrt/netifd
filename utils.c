#include <string.h>
#include "utils.h"

int
avl_strcmp(const void *k1, const void *k2, void *ptr)
{
	return strcmp(k1, k2);
}

static int
vlist_cmp(const void *k1, const void *k2, void *ptr)
{
	struct vlist_tree *vl = ptr;
	return memcmp(k1, k2, vl->data_len);
}

void
__vlist_init(struct vlist_tree *tree, vlist_update_cb update, int offset, int len)
{
	tree->data_offset = offset;
	tree->data_len = len;
	tree->update = update;
	tree->version = 1;

	avl_init(&tree->avl, vlist_cmp, 0, tree);
}

void
vlist_delete(struct vlist_tree *tree, struct vlist_node *node)
{
	avl_delete(&tree->avl, &node->avl);
	tree->update(tree, NULL, node);
}

void
vlist_add(struct vlist_tree *tree, struct vlist_node *node)
{
	struct vlist_node *old_node = NULL;
	struct avl_node *anode;

	node->avl.key = (char *) node + tree->data_offset;
	node->version = tree->version;

	anode = avl_find(&tree->avl, (char *) node + tree->data_offset);
	if (anode) {
		old_node = container_of(anode, struct vlist_node, avl);
		avl_delete(&tree->avl, anode);
	}

	avl_insert(&tree->avl, &node->avl);
	tree->update(tree, node, old_node);
}

void
vlist_flush(struct vlist_tree *tree)
{
	struct vlist_node *node, *tmp;

	avl_for_each_element_safe(&tree->avl, node, avl, tmp) {
		if (node->version == tree->version)
			continue;

		vlist_delete(tree, node);
	}
}

void
vlist_flush_all(struct vlist_tree *tree)
{
	tree->version++;
	vlist_flush(tree);
}
