/* "Sequence" lock primitive
 * Copyright (C) 2015  David Lamparter <equinox@diac24.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA
 */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <assert.h>

#include "seqlock.h"

#ifdef linux
#define USE_FUTEX
#endif /* linux */

#ifndef USE_FUTEX
/* generic version.  used on *BSD, Solaris and OSX.
 * at least on FreeBSD, umtx_op() doesn't support atomic compare-and-wait.
 */
#define wait_prep(sqlo)		pthread_mutex_lock(&sqlo->lock)
#define wait_once(sqlo, val)	pthread_cond_wait(&sqlo->wake, &sqlo->lock)
#define wait_done(sqlo)		pthread_mutex_unlock(&sqlo->lock)
#define wait_poke(sqlo)		do { \
		pthread_mutex_lock(&sqlo->lock); \
		pthread_cond_broadcast(&sqlo->wake); \
		pthread_mutex_unlock(&sqlo->lock); \
	} while (0)

#else /* USE_FUTEX */
/* Linux-specific version.  sys_futex() does compare-and-wait, yay! */

#include <unistd.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <linux/futex.h>

static long sys_futex(void *addr1, int op, int val1, struct timespec *timeout,
		void *addr2, int val3)
{
	return syscall(SYS_futex, addr1, op, val1, timeout, addr2, val3);
}

#define wait_prep(sqlo)
#define wait_once(sqlo, val)	\
	sys_futex((int *)&sqlo->work, FUTEX_WAIT, (int)val, NULL, NULL, 0);
#define wait_done(sqlo)
#define wait_poke(sqlo)		\
	sys_futex((int *)&sqlo->work, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
#endif



seqlock_val_t seqlock_ticket_get(struct seqlock *sqlo)
{
	return 1 + atomic_fetch_add_explicit(&sqlo->ticket, 1,
			memory_order_release);
}

void seqlock_ticket_wait(struct seqlock *sqlo, seqlock_val_t val)
{
	seqlock_val_t cur, cal;

	wait_prep(sqlo);
	while (1) {
		cur = atomic_load_explicit(&sqlo->work, memory_order_acquire);
		cal = cur - val;
		assert(cal < 0x40000000 || cal > 0xc0000000);
		if (cal < 0x80000000)
			break;

		wait_once(sqlo, cur);
	}
	wait_done(sqlo);
}

bool seqlock_ticket_check(struct seqlock *sqlo, seqlock_val_t val)
{
	seqlock_val_t cur;
	cur = atomic_load_explicit(&sqlo->work, memory_order_acquire);
	cur -= val;
	assert(cur < 0x40000000 || cur > 0xc0000000);
	return cur < 0x80000000;
}

seqlock_val_t seqlock_work_getticket(struct seqlock *sqlo)
{
	return atomic_load_explicit(&sqlo->ticket, memory_order_acquire);
}

void seqlock_work_set(struct seqlock *sqlo, seqlock_val_t val)
{
	atomic_store_explicit(&sqlo->work, val, memory_order_release);
	wait_poke(sqlo);
}

void seqlock_init(struct seqlock *sqlo)
{
	sqlo->work = 0;
	sqlo->ticket = 0;
#ifndef USE_FUTEX
	pthread_mutex_init (&sqlo->lock, NULL);
	pthread_cond_init (&sqlo->wake, NULL);
#endif
}

