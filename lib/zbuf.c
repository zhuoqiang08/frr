#include <zebra.h>
#include <unistd.h>
#include <errno.h>
#include "zassert.h"
#include "zbuf.h"
#include "memory.h"

#define ERRNO_IO_RETRY(EN) (((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

struct zbuf *zbuf_alloc(size_t size)
{
	struct zbuf *zb;

	zb = XMALLOC(MTYPE_TMP, sizeof(*zb) + size);
	if (!zb)
		return NULL;

	zbuf_init(zb, zb+1, size, 0);
	zb->allocated = 1;

	return zb;
}

void zbuf_init(struct zbuf *zb, void *buf, size_t len, size_t datalen)
{
	*zb = (struct zbuf) {
		.buf = buf,
		.end = (uint8_t *)buf + len,
		.head = buf,
		.tail = (uint8_t *)buf + datalen,
	};
}

void zbuf_free(struct zbuf *zb)
{
	if (zb->allocated)
		XFREE(MTYPE_TMP, zb);
}

void zbuf_reset(struct zbuf *zb)
{
	zb->head = zb->tail = zb->buf;
	zb->error = 0;
}

void zbuf_reset_head(struct zbuf *zb, void *ptr)
{
	zassert((void*)zb->buf <= ptr && ptr <= (void*)zb->tail);
	zb->head = ptr;
}

static void zbuf_remove_headroom(struct zbuf *zb)
{
	ssize_t headroom = zbuf_headroom(zb);
	if (!headroom)
		return;
	memmove(zb->buf, zb->head, zbuf_used(zb));
	zb->head -= headroom;
	zb->tail -= headroom;
}

ssize_t zbuf_read(struct zbuf *zb, int fd, size_t maxlen)
{
	ssize_t r;

	if (zb->error)
		return -3;

	zbuf_remove_headroom(zb);
	if (maxlen > zbuf_tailroom(zb))
		maxlen = zbuf_tailroom(zb);

	r = read(fd, zb->tail, maxlen);
	if (r > 0) zb->tail += r;
	else if (r == 0) r = -2;
	else if (r < 0 && ERRNO_IO_RETRY(errno)) r = 0;

	return r;
}

ssize_t zbuf_write(struct zbuf *zb, int fd)
{
	ssize_t r;

	if (zb->error)
		return -3;

	r = write(fd, zb->head, zbuf_used(zb));
	if (r > 0) {
		zb->head += r;
		if (zb->head == zb->tail)
			zbuf_reset(zb);
	}
	else if (r == 0) r = -2;
	else if (r < 0 && ERRNO_IO_RETRY(errno)) r = 0;

	return r;
}

ssize_t zbuf_recv(struct zbuf *zb, int fd)
{
	ssize_t r;

	if (zb->error)
		return -3;

	zbuf_remove_headroom(zb);
	r = recv(fd, zb->tail, zbuf_tailroom(zb), 0);
	if (r > 0) zb->tail += r;
	else if (r == 0) r = -2;
	else if (r < 0 && ERRNO_IO_RETRY(errno)) r = 0;
	return r;
}

ssize_t zbuf_send(struct zbuf *zb, int fd)
{
	ssize_t r;

	if (zb->error)
		return -3;

	r = send(fd, zb->head, zbuf_used(zb), 0);
	if (r >= 0)
		zbuf_reset(zb);

	return r;
}

void zbufq_init(struct zbuf_queue *zbq)
{
	*zbq = (struct zbuf_queue) {
		.queue_head = LIST_INITIALIZER(zbq->queue_head),
	};
}

void zbufq_reset(struct zbuf_queue *zbq)
{
	struct zbuf *buf, *bufn;

	list_for_each_entry_safe(buf, bufn, &zbq->queue_head, queue_list) {
		list_del(&buf->queue_list);
		zbuf_free(buf);
	}
}

void zbufq_queue(struct zbuf_queue *zbq, struct zbuf *zb)
{
	list_add_tail(&zb->queue_list, &zbq->queue_head);
}

int zbufq_write(struct zbuf_queue *zbq, int fd)
{
	struct iovec iov[16];
	struct zbuf *zb, *zbn;
	ssize_t r;
	size_t iovcnt = 0;

	list_for_each_entry_safe(zb, zbn, &zbq->queue_head, queue_list) {
		iov[iovcnt++] = (struct iovec) {
			.iov_base = zb->head,
			.iov_len = zbuf_used(zb),
		};
		if (iovcnt >= ZEBRA_NUM_OF(iov))
			break;
	}

	r = writev(fd, iov, iovcnt);
	if (r < 0)
		return r;

	list_for_each_entry_safe(zb, zbn, &zbq->queue_head, queue_list) {
		if (r < (ssize_t)zbuf_used(zb)) {
			zb->head += r;
			return 1;
		}

		r -= zbuf_used(zb);
		list_del(&zb->queue_list);
		zbuf_free(zb);
	}

	return 0;
}
