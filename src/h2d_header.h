#ifndef H2D_HTTP_H
#define H2D_HTTP_H

#include <string.h>

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

#define h2d_header_iter(list, h) wuy_slist_iter_type(list, h, list_node)

static inline void h2d_header_free_list(wuy_slist_t *list)
{
	struct h2d_header *h;
	while (wuy_slist_pop_type(list, h, list_node) != NULL) {
		free(h);
	}
}

#endif
