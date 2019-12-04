#ifndef H2D_HTTP_H
#define H2D_HTTP_H

#include <string.h>

struct h2d_header {
	short	name_len;
	short	value_len;
	char	str[0];
};

static inline const char *h2d_header_value(const struct h2d_header *h)
{
	return h->str + h->name_len + 1;
}
static inline struct h2d_header *h2d_header_next(const struct h2d_header *h)
{
	short len = sizeof(struct h2d_header) + h->name_len + h->value_len + 2;
	len += (len & 0x1); /* align at sizeof(short) */
	return (struct h2d_header *)((char *)h + len);
}

// TODO check end
static inline struct h2d_header *h2d_header_add(struct h2d_header *h,
		const char *name_str, int name_len,
		const char *value_str, int value_len)
{
	h->name_len = name_len;
	h->value_len = value_len;
	memcpy(h->str, name_str, name_len);
	h->str[name_len] = '\0';

	char *value_pos = h->str + name_len + 1;
	memcpy(value_pos, value_str, value_len);
	value_pos[value_len] = '\0';

	struct h2d_header *next = h2d_header_next(h);
	next->name_len = 0;
	return next;
}

#endif
