/*
 * Copyright (c) 2015  David Lamparter
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef _QUAGGA_QATOMIC_H
#define _QUAGGA_QATOMIC_H

#ifndef TRIED_ATOMIC
#error this header needs checks for stdatomic.h, did you include config.h?
#endif

#ifdef HAVE_STDATOMIC_H
#include <stdatomic.h>

#elif defined(HAVE___ATOMIC)

#define _Atomic volatile

#define memory_order_relaxed __ATOMIC_RELAXED
#define memory_order_consume __ATOMIC_CONSUME
#define memory_order_acquire __ATOMIC_ACQUIRE
#define memory_order_release __ATOMIC_RELEASE
#define memory_order_acq_rel __ATOMIC_ACQ_REL
#define memory_order_seq_cst __ATOMIC_SEQ_CST

#define atomic_load_explicit __atomic_load_n
#define atomic_store_explicit __atomic_store_n
#define atomic_exchange_explicit __atomic_exchange_n
#define atomic_fetch_add_explicit __atomic_fetch_add
#define atomic_fetch_sub_explicit __atomic_fetch_sub

#define atomic_compare_exchange_weak_explicit(atom, expect, desire, mem1, mem2) \
	__atomic_compare_exchange_n(atom, expect, desire, 1, mem1, mem2)

#define atomic_exchange(atom, val) \
	__atomic_exchange_n(atom, val, __ATOMIC_SEQ_CST)

#elif defined(HAVE___SYNC)

#define _Atomic volatile

#define memory_order_relaxed 0
#define memory_order_consume 0
#define memory_order_acquire 0
#define memory_order_release 0
#define memory_order_acq_rel 0
#define memory_order_seq_cst 0

#define atomic_load_explicit(ptr, mem) \
	({ __sync_fetch_and_add((ptr), 0); })
#define atomic_store_explicit(ptr, val, mem) \
	({ __sync_synchronize(); *(ptr) = (val); __sync_synchronize(); (void)0; })
#define atomic_exchange_explicit(ptr, val, mem) \
	({ typeof(ptr) _ptr = (ptr); typeof(val) _val = (val); \
	   typeof(*ptr) old1, old2 = __sync_fetch_and_add(_ptr, 0); \
	   do { \
		old1 = old2; \
		old2 = __sync_val_compare_and_swap (_ptr, old1, _val); \
	   } while (old1 != old2); \
	   old2; \
	})
#define atomic_fetch_add_explicit(ptr, val, mem) \
	({ __sync_fetch_and_add((ptr), (val)); })
#define atomic_fetch_sub_explicit(ptr, val, mem) \
	({ __sync_fetch_and_sub((ptr), (val)); })

#define atomic_compare_exchange_weak_explicit(atom, expect, desire, mem1, mem2) \
	({ typeof(atom) _atom = (atom); typeof(expect) _expect = (expect); \
	   typeof(desire) _desire = (desire); \
	   typeof(*atom) val = __sync_val_compare_and_swap(_atom, *_expect, _desire); \
	   bool ret = (val == *_expect); *_expect = val; ret; })

#define atomic_exchange(atom, val) atomic_exchange_explicit(atom, val, 0)

#else /* !HAVE___ATOMIC && !HAVE_STDATOMIC_H */
#error no atomic functions...
#endif

#endif /* _QUAGGA_QATOMIC_H */
