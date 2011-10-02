#ifndef __NETIFD_UTILS_H
#define __NETIFD_UTILS_H

#include <libubox/list.h>
#include <libubox/avl.h>

#ifdef DEBUG
#define DPRINTF(format, ...) fprintf(stderr, "%s(%d): " format, __func__, __LINE__, ## __VA_ARGS__)
#else
#define DPRINTF(format, ...) no_debug(format, ## __VA_ARGS__)
#endif

static inline void no_debug(const char *fmt, ...)
{
}

#define __init __attribute__((constructor))

struct vlist_tree;
struct vlist_node;

typedef void (*vlist_update_cb)(struct vlist_tree *tree,
				struct vlist_node *node_new,
				struct vlist_node *node_old);

struct vlist_tree {
	struct avl_tree avl;

	vlist_update_cb update;
	int key_offset;
	bool keep_old;

	int version;
};

struct vlist_node {
	struct avl_node avl;
	int version;
};

void __vlist_init(struct vlist_tree *tree, avl_tree_comp cmp, vlist_update_cb update, int offset);

#define vlist_init(tree, cmp, update, type, node, key) \
	__vlist_init(tree, cmp, update, offsetof(type, key) - offsetof(type, node))

void vlist_add(struct vlist_tree *tree, struct vlist_node *node);
void vlist_delete(struct vlist_tree *tree, struct vlist_node *node);
void vlist_flush(struct vlist_tree *tree);
void vlist_flush_all(struct vlist_tree *tree);

#define vlist_for_each_element(tree, element, node_member) \
	avl_for_each_element(&(tree)->avl, element, node_member.avl)

#ifdef __linux__
static inline int fls(int x)
{
    int r = 32;

    if (!x)
        return 0;
    if (!(x & 0xffff0000u)) {
        x <<= 16;
        r -= 16;
    }
    if (!(x & 0xff000000u)) {
        x <<= 8;
        r -= 8;
    }
    if (!(x & 0xf0000000u)) {
        x <<= 4;
        r -= 4;
    }
    if (!(x & 0xc0000000u)) {
        x <<= 2;
        r -= 2;
    }
    if (!(x & 0x80000000u)) {
        x <<= 1;
        r -= 1;
    }
    return r;
}
#endif

int avl_strcmp(const void *k1, const void *k2, void *ptr);

#endif
