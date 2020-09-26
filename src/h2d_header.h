#ifndef H2D_HTTP_H
#define H2D_HTTP_H

#include <string.h>
#include <stdlib.h>

struct h2d_header {
	wuy_slist_node_t	list_node;
	short			name_len;
	short			value_len;
	char			str[0];
};

static inline char *h2d_header_value(struct h2d_header *h)
{
	return h->str + h->name_len + 1;
}

static inline struct h2d_header *h2d_header_new(const char *name_str, int name_len,
		const char *value_str, int value_len)
{
	struct h2d_header *h = malloc(sizeof(struct h2d_header) + name_len + value_len + 2);
	if (h == NULL) {
		return NULL;
	}
	h->name_len = name_len;
	h->value_len = value_len;

	memcpy(h->str, name_str, name_len);
	h->str[name_len] = '\0';

	char *value_pos = h2d_header_value(h);
	memcpy(value_pos, value_str, value_len);
	value_pos[value_len] = '\0';

	return h;
}

#define h2d_header_add_lite(list, name, value, value_len) \
	h2d_header_add(list, name, sizeof(name)-1, value, value_len)

static inline struct h2d_header *h2d_header_add(wuy_slist_t *list,
		const char *name_str, int name_len,
		const char *value_str, int value_len)
{
	struct h2d_header *h = h2d_header_new(name_str, name_len, value_str, value_len);
	if (h == NULL) {
		return NULL;
	}
	wuy_slist_append(list, &h->list_node);
	return h;
}

static inline struct h2d_header *h2d_header_get(wuy_slist_t *list, const char *name)
{
	struct h2d_header *h;
	wuy_slist_iter_type(list, h, list_node) {
		if (strcasecmp(h->str, name) == 0) {
			return h;
		}
	}
	return NULL;
}

#define h2d_header_iter(list, h) wuy_slist_iter_type(list, h, list_node)

static inline void h2d_header_free_list(wuy_slist_t *list)
{
	struct h2d_header *h;
	while (wuy_slist_pop_type(list, h, list_node) != NULL) {
		free(h);
	}
}

static inline void h2d_header_dup_list(wuy_slist_t *to, wuy_slist_t *from)
{
	struct h2d_header *h;
	wuy_slist_iter_type(from, h, list_node) {
		h2d_header_add(to, h->str, h->name_len, h2d_header_value(h), h->value_len);
	}
}

#endif
