/*
 * Memory management routine
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#include <zebra.h>
/* malloc.h is generally obsolete, however GNU Libc mallinfo wants it. */
#if !defined(HAVE_STDLIB_H) || (defined(GNU_LINUX) && defined(HAVE_MALLINFO))
#include <malloc.h>
#endif /* !HAVE_STDLIB_H || HAVE_MALLINFO */

#include "log.h"
#include "memory.h"
#include "memory_cli.h"

/* Looking up memory status from vty interface. */
#include "vector.h"
#include "vty.h"
#include "command.h"

void
log_memstats_stderr (const char *prefix)
{
#if 0
  struct mlist *ml;
  struct memory_list *m;
  int i;
  int j = 0;

  for (ml = mlists; ml->list; ml++)
    {
      i = 0;

      for (m = ml->list; m->index >= 0; m++)
        if (m->index && mstat[m->index].alloc)
          {
            if (!i)
              fprintf (stderr,
                       "%s: memstats: Current memory utilization in module %s:\n",
                       prefix,
                       ml->name);
            fprintf (stderr,
                     "%s: memstats:  %-30s: %10ld%s\n",
                     prefix,
                     m->format,
                     mstat[m->index].alloc,
                     mstat[m->index].alloc < 0 ? " (REPORT THIS BUG!)" : "");
            i = j = 1;
          }
    }

  if (j)
    fprintf (stderr,
             "%s: memstats: NOTE: If configuration exists, utilization may be "
             "expected.\n",
             prefix);
  else
    fprintf (stderr,
             "%s: memstats: No remaining tracked memory utilization.\n",
             prefix);
#endif
}

#if 0
static void
show_separator(struct vty *vty)
{
  vty_out (vty, "-----------------------------\r\n");
}

static int
show_memory_vty (struct vty *vty, struct memory_list *list)
{
  struct memory_list *m;
  int needsep = 0;

  for (m = list; m->index >= 0; m++)
    if (m->index == 0)
      {
	if (needsep)
	  {
	    show_separator (vty);
	    needsep = 0;
	  }
      }
    else if (mstat[m->index].alloc)
      {
	vty_out (vty, "%-30s: %10ld\r\n", m->format, mstat[m->index].alloc);
	needsep = 1;
      }
  return needsep;
}
#endif

#ifdef HAVE_MALLINFO
static int
show_memory_mallinfo (struct vty *vty)
{
  struct mallinfo minfo = mallinfo();
  char buf[MTYPE_MEMSTR_LEN];
  
  vty_out (vty, "System allocator statistics:%s", VTY_NEWLINE);
  vty_out (vty, "  Total heap allocated:  %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.arena),
           VTY_NEWLINE);
  vty_out (vty, "  Holding block headers: %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.hblkhd),
           VTY_NEWLINE);
  vty_out (vty, "  Used small blocks:     %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.usmblks),
           VTY_NEWLINE);
  vty_out (vty, "  Used ordinary blocks:  %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.uordblks),
           VTY_NEWLINE);
  vty_out (vty, "  Free small blocks:     %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.fsmblks),
           VTY_NEWLINE);
  vty_out (vty, "  Free ordinary blocks:  %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.fordblks),
           VTY_NEWLINE);
  vty_out (vty, "  Ordinary blocks:       %ld%s",
           (unsigned long)minfo.ordblks,
           VTY_NEWLINE);
  vty_out (vty, "  Small blocks:          %ld%s",
           (unsigned long)minfo.smblks,
           VTY_NEWLINE);
  vty_out (vty, "  Holding blocks:        %ld%s",
           (unsigned long)minfo.hblks,
           VTY_NEWLINE);
  vty_out (vty, "(see system documentation for 'mallinfo' for meaning)%s",
           VTY_NEWLINE);
  return 1;
}
#endif /* HAVE_MALLINFO */

static int qmem_walker(void *arg, struct memgroup *mg, struct memtype *mt)
{
	struct vty *vty = arg;
	if (!mt)
		vty_out (vty, "--- qmem %s ---%s", mg->name, VTY_NEWLINE);
	else {
		char size[32];
		snprintf(size, sizeof(size), "%6ld", mt->size);
		vty_out (vty, "%-30s: %10ld  %s%s",
			mt->name, mt->n_alloc,
			mt->size == 0 ? "" :
			mt->size == SIZE_VAR ? "(variably sized)" :
			size, VTY_NEWLINE);
	}
	return 0;
}


DEFUN (show_memory_all,
       show_memory_all_cmd,
       "show memory all",
       "Show running system information\n"
       "Memory statistics\n"
       "All memory statistics\n")
{
  int needsep = 0;
  
#ifdef HAVE_MALLINFO
  needsep = show_memory_mallinfo (vty);
#endif /* HAVE_MALLINFO */

  (void) needsep;
#if 0
  struct mlist *ml;
  for (ml = mlists; ml->list; ml++)
    {
      if (needsep)
	show_separator (vty);
      needsep = show_memory_vty (vty, ml->list);
    }
#endif

  qmem_walk(qmem_walker, vty);
  return CMD_SUCCESS;
}

ALIAS (show_memory_all,
       show_memory_cmd,
       "show memory",
       "Show running system information\n"
       "Memory statistics\n")

DEFUN (show_memory_lib,
       show_memory_lib_cmd,
       "show memory lib",
       SHOW_STR
       "Memory statistics\n"
       "Library memory\n")
{
  return CMD_SUCCESS;
}

DEFUN (show_memory_zebra,
       show_memory_zebra_cmd,
       "show memory zebra",
       SHOW_STR
       "Memory statistics\n"
       "Zebra memory\n")
{
  return CMD_SUCCESS;
}

DEFUN (show_memory_rip,
       show_memory_rip_cmd,
       "show memory rip",
       SHOW_STR
       "Memory statistics\n"
       "RIP memory\n")
{
  return CMD_SUCCESS;
}

DEFUN (show_memory_ripng,
       show_memory_ripng_cmd,
       "show memory ripng",
       SHOW_STR
       "Memory statistics\n"
       "RIPng memory\n")
{
  return CMD_SUCCESS;
}

DEFUN (show_memory_babel,
       show_memory_babel_cmd,
       "show memory babel",
       SHOW_STR
       "Memory statistics\n"
       "Babel memory\n")
{
  return CMD_SUCCESS;
}

DEFUN (show_memory_bgp,
       show_memory_bgp_cmd,
       "show memory bgp",
       SHOW_STR
       "Memory statistics\n"
       "BGP memory\n")
{
  return CMD_SUCCESS;
}

DEFUN (show_memory_ospf,
       show_memory_ospf_cmd,
       "show memory ospf",
       SHOW_STR
       "Memory statistics\n"
       "OSPF memory\n")
{
  return CMD_SUCCESS;
}

DEFUN (show_memory_ospf6,
       show_memory_ospf6_cmd,
       "show memory ospf6",
       SHOW_STR
       "Memory statistics\n"
       "OSPF6 memory\n")
{
  return CMD_SUCCESS;
}

DEFUN (show_memory_isis,
       show_memory_isis_cmd,
       "show memory isis",
       SHOW_STR
       "Memory statistics\n"
       "ISIS memory\n")
{
  return CMD_SUCCESS;
}

DEFUN (show_memory_pim,
       show_memory_pim_cmd,
       "show memory pim",
       SHOW_STR
       "Memory statistics\n"
       "PIM memory\n")
{
  return CMD_SUCCESS;
}

void
memory_init (void)
{
  install_element (RESTRICTED_NODE, &show_memory_cmd);
  install_element (RESTRICTED_NODE, &show_memory_all_cmd);
  install_element (RESTRICTED_NODE, &show_memory_lib_cmd);
  install_element (RESTRICTED_NODE, &show_memory_rip_cmd);
  install_element (RESTRICTED_NODE, &show_memory_ripng_cmd);
  install_element (RESTRICTED_NODE, &show_memory_babel_cmd);
  install_element (RESTRICTED_NODE, &show_memory_bgp_cmd);
  install_element (RESTRICTED_NODE, &show_memory_ospf_cmd);
  install_element (RESTRICTED_NODE, &show_memory_ospf6_cmd);
  install_element (RESTRICTED_NODE, &show_memory_isis_cmd);

  install_element (VIEW_NODE, &show_memory_cmd);
  install_element (VIEW_NODE, &show_memory_all_cmd);
  install_element (VIEW_NODE, &show_memory_lib_cmd);
  install_element (VIEW_NODE, &show_memory_rip_cmd);
  install_element (VIEW_NODE, &show_memory_ripng_cmd);
  install_element (VIEW_NODE, &show_memory_babel_cmd);
  install_element (VIEW_NODE, &show_memory_bgp_cmd);
  install_element (VIEW_NODE, &show_memory_ospf_cmd);
  install_element (VIEW_NODE, &show_memory_ospf6_cmd);
  install_element (VIEW_NODE, &show_memory_isis_cmd);
  install_element (VIEW_NODE, &show_memory_pim_cmd);

  install_element (ENABLE_NODE, &show_memory_cmd);
  install_element (ENABLE_NODE, &show_memory_all_cmd);
  install_element (ENABLE_NODE, &show_memory_lib_cmd);
  install_element (ENABLE_NODE, &show_memory_zebra_cmd);
  install_element (ENABLE_NODE, &show_memory_rip_cmd);
  install_element (ENABLE_NODE, &show_memory_ripng_cmd);
  install_element (ENABLE_NODE, &show_memory_babel_cmd);
  install_element (ENABLE_NODE, &show_memory_bgp_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf6_cmd);
  install_element (ENABLE_NODE, &show_memory_isis_cmd);
  install_element (ENABLE_NODE, &show_memory_pim_cmd);
}

/* Stats querying from users */
/* Return a pointer to a human friendly string describing
 * the byte count passed in. E.g:
 * "0 bytes", "2048 bytes", "110kB", "500MiB", "11GiB", etc.
 * Up to 4 significant figures will be given.
 * The pointer returned may be NULL (indicating an error)
 * or point to the given buffer, or point to static storage.
 */
const char *
mtype_memstr (char *buf, size_t len, unsigned long bytes)
{
  unsigned int t, g, m, k;
  
  /* easy cases */
  if (!bytes)
    return "0 bytes";
  if (bytes == 1)
    return "1 byte";
    
  if (sizeof (unsigned long) >= 8)
    /* Hacked to make it not warn on ILP32 machines
     * Shift will always be 40 at runtime. See below too */
    t = bytes >> (sizeof (unsigned long) >= 8 ? 40 : 0);
  else
    t = 0;
  g = bytes >> 30;
  m = bytes >> 20;
  k = bytes >> 10;
  
  if (t > 10)
    {
      /* The shift will always be 39 at runtime.
       * Just hacked to make it not warn on 'smaller' machines. 
       * Static compiler analysis should mean no extra code
       */
      if (bytes & (1UL << (sizeof (unsigned long) >= 8 ? 39 : 0)))
        t++;
      snprintf (buf, len, "%4d TiB", t);
    }
  else if (g > 10)
    {
      if (bytes & (1 << 29))
        g++;
      snprintf (buf, len, "%d GiB", g);
    }
  else if (m > 10)
    {
      if (bytes & (1 << 19))
        m++;
      snprintf (buf, len, "%d MiB", m);
    }
  else if (k > 10)
    {
      if (bytes & (1 << 9))
        k++;
      snprintf (buf, len, "%d KiB", k);
    }
  else
    snprintf (buf, len, "%ld bytes", bytes);
  
  return buf;
}
