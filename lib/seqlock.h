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

#ifndef _SEQLOCK_H
#define _SEQLOCK_H

#include <stdbool.h>
#include <pthread.h>
#include "qatomic.h"

typedef _Atomic unsigned	seqlock_ctr_t;
typedef unsigned		seqlock_val_t;

struct seqlock {
/* always used */
	volatile seqlock_ctr_t work;
	volatile seqlock_ctr_t ticket;
/* used when futexes not available: (i.e. non-linux) */
	pthread_mutex_t lock;
	pthread_cond_t  wake;
};

extern seqlock_val_t seqlock_ticket_get(struct seqlock *sqlo);
extern void seqlock_ticket_wait(struct seqlock *sqlo, seqlock_val_t val);
extern bool seqlock_ticket_check(struct seqlock *sqlo, seqlock_val_t val);

static inline void seqlock_ticket_getwait (struct seqlock *sqlo)
{
	seqlock_val_t ticket = seqlock_ticket_get(sqlo);
	seqlock_ticket_wait(sqlo, ticket);
}

extern seqlock_val_t seqlock_work_getticket(struct seqlock *sqlo);
extern void seqlock_work_set(struct seqlock *sqlo, seqlock_val_t val);

extern void seqlock_init(struct seqlock *sqlo);

#endif /* _SEQLOCK_H */
