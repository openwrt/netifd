#include <string.h>
#include <stdlib.h>
#include "utils.h"

int
avl_strcmp(const void *k1, const void *k2, void *ptr)
{
	return strcmp(k1, k2);
}

void
__vlist_init(struct vlist_tree *tree, avl_tree_comp cmp,
	     vlist_update_cb update, int offset)
{
	tree->key_offset = offset;
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
vlist_add(struct vlist_tree *tree, struct vlist_node *node)
{
	struct vlist_node *old_node = NULL;
	struct avl_node *anode;
	void *key = (char *) node + tree->key_offset;

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
		if (n->version == tree->version)
			continue;

		vlist_simple_delete(tree, n);
	}
}

void
vlist_simple_flush_all(struct vlist_simple_tree *tree)
{
	tree->version++;
	vlist_simple_flush(tree);
}
