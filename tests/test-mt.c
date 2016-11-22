/*
 * CLI/command dummy handling tester
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#define _GNU_SOURCE
#ifdef linux
#include <sys/syscall.h>
#endif
#include "common-cli.h"
#include "memory.h"

struct thread_master *masters[4] = { NULL };
thread_ref_t refs[4] = {
        THREAD_REF_INIT, THREAD_REF_INIT, THREAD_REF_INIT, THREAD_REF_INIT,
//        THREAD_REF_INIT, THREAD_REF_INIT, THREAD_REF_INIT, THREAD_REF_INIT,
};

DEFUN(master_fork,
      master_fork_cmd,
      "master fork NUM",
      "Thread master\n"
      "fork a new one\n"
      "number\n")
{
  int num = atoi(argv[0]);
  if ((size_t)num >= array_size (masters))
    return CMD_WARNING;
  if (masters[num])
    {
      vty_out (vty, "master %d already exists: %p (%d)%s",
                    num, (void *)masters[num], masters[num]->tid, VTY_NEWLINE);
      return CMD_WARNING;
    }
  masters[num] = thread_master_fork ();
  vty_out (vty, "master %d forked: %p (%d)%s",
                num, (void *)masters[num], masters[num]->tid, VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN(master_show,
      master_show_cmd,
      "master show",
      "Thread master\n"
      "list\n")
{
  size_t i;
  for (i = 0; i < array_size(masters); i++)
    {
      if (masters[i])
        vty_out (vty, "master %2zu: %10p (%6d)%s",
                      i, (void *)masters[i], masters[i]->tid, VTY_NEWLINE);
      else
        vty_out (vty, "master %2zu: -%s", i, VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

static int thread_func (struct thread *thr)
{
#ifdef linux
  pid_t tid = syscall (SYS_gettid);
#else
  pid_t tid = 0;
#endif
  fprintf (stderr, "\r\033[K(%ld: %p) running\r\n",
                   (long)tid, (void *)thr);
  return 0;
}

DEFUN(thread_sched,
      thread_sched_cmd,
      "thread sched MASTER DELAY",
      "Threads\n"
      "schedule one\n"
      "number of master to use\n"
      "delay in deciseconds\n")
{
  struct thread_master *m;
  struct thread *t;
  int num = atoi(argv[0]);
  int delay = atoi(argv[1]);

  if ((size_t)num >= array_size (masters) || delay < 0)
    return CMD_WARNING;
  m = masters[num];
  if (!m)
    {
      vty_out (vty, "no such master%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  t = thread_add_timer_msec (m, thread_func, NULL, delay * 100);
  vty_out (vty, "scheduled thread %p on master %p%s",
                (void *)t, (void *)m, VTY_NEWLINE);
  return CMD_SUCCESS;
}

struct reader {
  int fd;
  int resched;
  thread_ref_t *ref;
};

static int thread_reader_func (struct thread *thr)
{
#ifdef linux
  pid_t tid = syscall (SYS_gettid);
#else
  pid_t tid = 0;
#endif
  struct reader *r = THREAD_ARG (thr);
  char buf[256];
  ssize_t nread = read(r->fd, buf, sizeof(buf) - 1);

  if (nread <= 0)
    {
      fprintf (stderr, "\r\033[K(%ld: %p) read returned %ld (%s)\r\n",
                       (long) tid, (void *)thr, (long)nread, strerror(errno));
      free (r);
      return 0;
    }
  buf[nread] = '\0';
  if (buf[nread - 1] == '\n')
    buf[nread - 1] = '\0';
  fprintf (stderr, "\r\033[K(%ld: %p) read: \"%s\"\r\n",
                   (long) tid, (void *)thr, buf);

  if (!strcmp (buf, "exit"))
    {
      fprintf (stderr, "\r\033[K(%ld: %p) is end command\r\n",
                       (long) tid, (void *)thr);
      free (r);
      return 0;
    }
  if (r->resched)
    {
      struct thread *next = thread_ref_add_read (thr->master, r->ref,
                thread_reader_func, r, THREAD_FD (thr));
      fprintf (stderr, "\r\033[K(%ld: %p) resched => %p\r\n",
                       (long) tid, (void *)thr, (void *)next);
    }
  else
    free (r);
  return 0;
}

DEFUN(thread_reader,
      thread_reader_cmd,
      "thread reader {master MASTER|fd FD|resched RESCHED|ref REFNO}",
      "Threads\n"
      "add a reader\n"
      "select thread master\n"
      "number of master to use\n"
      "select fd\n"
      "fd number\n"
      "select operation\n"
      "run continuous?\n"
      "select reference\n"
      "reference number\n")
{
  struct thread_master *m;
  struct thread *t;
  int num = atoi(argv[0]);
  int fd = atoi(argv[1]);
  int resched = argv[2] ? atoi(argv[2]) : 0;
  thread_ref_t *ref = NULL;

  if ((size_t)num >= array_size (masters) || fd < 3)
    return CMD_WARNING;
  m = masters[num];
  if (!m)
    {
      vty_out (vty, "no such master%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argv[3])
    {
      int refno = atoi(argv[3]);
      if ((size_t)refno >= array_size (refs))
        return CMD_WARNING;
      ref = refs + refno;
    }

  struct reader *rdr = malloc(sizeof(struct reader));
  rdr->fd = fd;
  rdr->resched = resched;
  rdr->ref = ref;

  t = thread_ref_add_read (m, ref, thread_reader_func, rdr, fd);
  vty_out (vty, "scheduled thread %p on master %p, ref %p%s",
                (void *)t, (void *)m, (void *)ref, VTY_NEWLINE);
  return CMD_SUCCESS;
}

static const char *states[] = { "EMPTY", "SCHED", "RUNNING", "CANCEL" };

DEFUN(thread_refshow,
      thread_refshow_cmd,
      "thread ref show",
      "Threads\n"
      "references\n"
      "show\n")
{
  size_t i;

  for (i = 0; i < array_size(refs); i++)
    {
      vty_out (vty, "ref %2zu: %18p %-7s %p%s",
                    i, (void *)&refs[i], states[refs[i].status],
                    (void *)refs[i].thread, VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN(thread_refcancel,
      thread_refcancel_cmd,
      "thread ref cancel NUM",
      "Threads\n"
      "references\n"
      "cancel\n"
      "reference number\n")
{
  int i = atoi(argv[0]);
  if ((size_t)i > array_size(refs))
    return CMD_WARNING;

  vty_out (vty, "+++ %2d: %18p %-7s %p%s",
                i, (void *)&refs[i], states[refs[i].status],
                (void *)refs[i].thread, VTY_NEWLINE);
  thread_cancel_async (&refs[i]);
  vty_out (vty, "--- %2d: %18p %-7s %p%s",
                i, (void *)&refs[i], states[refs[i].status],
                (void *)refs[i].thread, VTY_NEWLINE);
  return CMD_SUCCESS;
}

void test_init(void)
{
  masters[0] = master;
  install_element (ENABLE_NODE, &master_fork_cmd);
  install_element (ENABLE_NODE, &master_show_cmd);
  install_element (ENABLE_NODE, &thread_sched_cmd);
  install_element (ENABLE_NODE, &thread_reader_cmd);
  install_element (ENABLE_NODE, &thread_refshow_cmd);
  install_element (ENABLE_NODE, &thread_refcancel_cmd);
}
