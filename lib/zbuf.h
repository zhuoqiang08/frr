/*
 * Stream/packet buffer interface
 * Copyright (C) 2015 Timo Teräs
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef ZBUF_H
#define ZBUF_H

#include <stdint.h>
#include <string.h>
#include <endian.h>
#include <sys/types.h>

#include "zassert.h"
#include "list.h"

struct zbuf {
	struct list_head queue_list;
	unsigned allocated : 1;
	unsigned error : 1;
	uint8_t *buf, *end;
	uint8_t *head, *tail;
};

struct zbuf_queue {
	struct list_head queue_head;
};

struct zbuf *zbuf_alloc(size_t size);
void zbuf_init(struct zbuf *zb, void *buf, size_t len, size_t datalen);
void zbuf_free(struct zbuf *zb);

static inline size_t zbuf_size(struct zbuf *zb)
{
	return zb->end - zb->buf;
}

static inline size_t zbuf_used(struct zbuf *zb)
{
	return zb->tail - zb->head;
}

static inline size_t zbuf_tailroom(struct zbuf *zb)
{
	return zb->end - zb->tail;
}

static inline size_t zbuf_headroom(struct zbuf *zb)
{
	return zb->head - zb->buf;
}

void zbuf_reset(struct zbuf *zb);
void zbuf_reset_head(struct zbuf *zb, void *ptr);
ssize_t zbuf_read(struct zbuf *zb, int fd, size_t maxlen);
ssize_t zbuf_write(struct zbuf *zb, int fd);
ssize_t zbuf_recv(struct zbuf *zb, int fd);
ssize_t zbuf_send(struct zbuf *zb, int fd);

static inline void zbuf_set_werror(struct zbuf *zb)
{
	zb->error = 1;
	zb->head = zb->tail;
}

static inline void *__zbuf_pull(struct zbuf *zb, size_t size, int error)
{
	void *head = zb->head;
	if (size > zbuf_used(zb)) {
		if (error) zbuf_set_werror(zb);
		return NULL;
	}
	zb->head += size;
	return head;
}

#define zbuf_pull(zb, type) ((type *)__zbuf_pull(zb, sizeof(type), 1))
#define zbuf_pulln(zb, sz) ((void *)__zbuf_pull(zb, sz, 1))
#define zbuf_may_pull(zb, type) ((type *)__zbuf_pull(zb, sizeof(type), 0))
#define zbuf_may_pulln(zb, sz) ((void *)__zbuf_pull(zb, sz, 0))

void *zbuf_may_pull_until(struct zbuf *zb, const char *sep, struct zbuf *msg);

static inline void zbuf_get(struct zbuf *zb, void *dst, size_t len)
{
	void *src = zbuf_pulln(zb, len);
	if (src) memcpy(dst, src, len);
}

static inline uint8_t zbuf_get8(struct zbuf *zb)
{
	uint8_t *src = zbuf_pull(zb, uint8_t);
	if (src) return *src;
	return 0;
}

static inline uint16_t zbuf_get16(struct zbuf *zb)
{
	struct unaligned16 {
		uint16_t value;
	} __attribute__((packed));

	struct unaligned16 *v = zbuf_pull(zb, struct unaligned16);
	if (v) return v->value;
	return 0;
}

static inline uint16_t zbuf_get_be16(struct zbuf *zb)
{
	struct unaligned16 {
		uint16_t value;
	} __attribute__((packed));

	struct unaligned16 *v = zbuf_pull(zb, struct unaligned16);
	if (v) return be16toh(v->value);
	return 0;
}

static inline uint32_t zbuf_get_be32(struct zbuf *zb)
{
	struct unaligned32 {
		uint32_t value;
	} __attribute__((packed));

	struct unaligned32 *v = zbuf_pull(zb, struct unaligned32);
	if (v) return be32toh(v->value);
	return 0;
}

static inline void *__zbuf_push(struct zbuf *zb, size_t size, int error)
{
	void *tail = zb->tail;
	if (size > zbuf_tailroom(zb)) {
		if (error) {
			zb->error = 1;
			zb->tail = zb->end;
		}
		return NULL;
	}
	zb->tail += size;
	return tail;
}

#define zbuf_push(zb, type) ((type *)__zbuf_push(zb, sizeof(type), 1))
#define zbuf_pushn(zb, sz) ((void *)__zbuf_push(zb, sz, 1))
#define zbuf_may_push(zb, type) ((type *)__zbuf_may_push(zb, sizeof(type), 0))
#define zbuf_may_pushn(zb, sz) ((void *)__zbuf_push(zb, sz, 0))

static inline void zbuf_put(struct zbuf *zb, const void *src, size_t len)
{
	void *dst = zbuf_pushn(zb, len);
	if (dst) memcpy(dst, src, len);
}

static inline void zbuf_put8(struct zbuf *zb, uint8_t val)
{
	uint8_t *dst = zbuf_push(zb, uint8_t);
	if (dst) *dst = val;
}

static inline void zbuf_put_be16(struct zbuf *zb, uint16_t val)
{
	struct unaligned16 {
		uint16_t value;
	} __attribute__((packed));

	struct unaligned16 *v = zbuf_push(zb, struct unaligned16);
	if (v) v->value = htobe16(val);
}

static inline void zbuf_put_be32(struct zbuf *zb, uint32_t val)
{
	struct unaligned32 {
		uint32_t value;
	} __attribute__((packed));

	struct unaligned32 *v = zbuf_push(zb, struct unaligned32);
	if (v) v->value = htobe32(val);
}


void zbufq_init(struct zbuf_queue *);
void zbufq_reset(struct zbuf_queue *);
void zbufq_queue(struct zbuf_queue *, struct zbuf *);
int zbufq_write(struct zbuf_queue *, int);

#endif
