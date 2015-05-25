#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "seqlock.h"

static struct seqlock sqlo;
static pthread_t thr1;

#define writestr(str) write(1, str, strlen(str))

static void *thr1func(void *arg)
{
	seqlock_ticket_wait(&sqlo, 2);
	writestr("thr1 @2\n");
	seqlock_ticket_wait(&sqlo, 3);
	writestr("thr1 @3\n");
	seqlock_ticket_wait(&sqlo, 4);
	writestr("thr1 @4\n");
	seqlock_ticket_wait(&sqlo, 5);
	writestr("thr1 @5\n");
	seqlock_ticket_wait(&sqlo, 8);
	writestr("thr1 @8\n");
	return NULL;
}

int main()
{
	seqlock_init(&sqlo);
	
	assert(seqlock_ticket_get(&sqlo) == 1);
	assert(seqlock_ticket_get(&sqlo) == 2);
	assert(seqlock_ticket_get(&sqlo) == 3);
	assert(seqlock_work_getticket(&sqlo) == 3);
	seqlock_work_set(&sqlo, 2);

	pthread_create(&thr1, NULL, thr1func, NULL);
	sleep(1);
	writestr("main >4\n");
	seqlock_work_set(&sqlo, 4);
	sleep(1);
	writestr("main >5\n");
	seqlock_work_set(&sqlo, 5);
	sleep(1);
	writestr("main >6\n");
	seqlock_work_set(&sqlo, 6);
	sleep(1);
	writestr("main >7\n");
	seqlock_work_set(&sqlo, 7);
	sleep(1);
	writestr("main >8\n");
	seqlock_work_set(&sqlo, 8);
	sleep(1);
	writestr("main >9\n");
	seqlock_work_set(&sqlo, 9);
	sleep(1);
}

