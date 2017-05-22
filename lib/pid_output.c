/*
 * Process id output.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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
#include <fcntl.h>
#include <log.h>
#include "version.h"
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#define PIDFILE_MASK 0644

pid_t proc_find(const char* name) 
{
  DIR* dir;
  struct dirent* ent;
  char* endptr;
  char buf[512];

  if (!(dir = opendir("/proc"))) {
    perror("can't open /proc");
    return -1;
  }

  while((ent = readdir(dir)) != NULL) {
    /* if endptr is not a null character, the directory is not
     * entirely numeric, so ignore it */
    long lpid = strtol(ent->d_name, &endptr, 10);
    if (*endptr != '\0') {
      continue;
    }
    if (lpid == getpid())
      continue;
    /* try to open the cmdline file */
    snprintf(buf, sizeof(buf), "/proc/%ld/cmdline", lpid);
    FILE* fp = fopen(buf, "r");

    if (fp) {
      if (fgets(buf, sizeof(buf), fp) != NULL) {
        /* check the first token in the file, the program name */
        char* first = strtok(buf, " ");
        if (!strcmp(first, name)) {
          fclose(fp);
          closedir(dir);
          return (pid_t)lpid;
        }
      }
      fclose(fp);
    }

  }

  closedir(dir);
  return -1;
}

#ifndef HAVE_FCNTL

pid_t
pid_output (const char *path)
{
  FILE *fp;
  pid_t pid;
  mode_t oldumask;

  pid = getpid();

  oldumask = umask(0777 & ~PIDFILE_MASK);
  fp = fopen (path, "w");
  if (fp != NULL) 
    {
      fprintf (fp, "%d\n", (int) pid);
      fclose (fp);
      umask(oldumask);
      return pid;
    }
  /* XXX Why do we continue instead of exiting?  This seems incompatible
     with the behavior of the fcntl version below. */
  zlog_warn("Can't fopen pid lock file %s (%s), continuing",
	    path, safe_strerror(errno));
  umask(oldumask);
  return -1;
}

/*
 * read pid number in file
 * return pid id if valid, 0 otherwise
 */
pid_t
get_pid_output (const char *path)
{
  FILE *fp;
  pid_t pid;

  fp = fopen (path, "r");
  if (fp != NULL)
    {
      sscanf (fp, "%d\n", &pid);
      fclose (fp);
      return pid;
    }
  /* XXX Why do we continue instead of exiting?  This seems incompatible
     with the behavior of the fcntl version below. */
  zlog_warn("Can't fopen pid lock file %s (%s), continuing",
	    path, safe_strerror(errno));
  return 0;
}

#else /* HAVE_FCNTL */

pid_t
pid_output (const char *path)
{
  int tmp;
  int fd;
  pid_t pid;
  char buf[16];
  struct flock lock;  
  mode_t oldumask;

  pid = getpid ();

  oldumask = umask(0777 & ~PIDFILE_MASK);
  fd = open (path, O_RDWR | O_CREAT, PIDFILE_MASK);
  if (fd < 0)
    {
      zlog_err("Can't create pid lock file %s (%s), exiting",
	       path, safe_strerror(errno));
      umask(oldumask);
      exit(1);
    }
  else
    {
      size_t pidsize;

      umask(oldumask);
      memset (&lock, 0, sizeof(lock));

      lock.l_type = F_WRLCK;
      lock.l_whence = SEEK_SET;

      if (fcntl(fd, F_SETLK, &lock) < 0)
        {
          zlog_err("Could not lock pid_file %s, exiting", path);
          exit(1);
        }

      sprintf (buf, "%d\n", (int) pid);
      pidsize = strlen(buf);
      if ((tmp = write (fd, buf, pidsize)) != (int)pidsize)
        zlog_err("Could not write pid %d to pid_file %s, rc was %d: %s",
	         (int)pid,path,tmp,safe_strerror(errno));
      else if (ftruncate(fd, pidsize) < 0)
        zlog_err("Could not truncate pid_file %s to %u bytes: %s",
	         path,(u_int)pidsize,safe_strerror(errno));
      close(fd);
    }
  return pid;
}

/*
 * read pid number in file
 * return pid id if valid, 0 otherwise
 */
pid_t
get_pid_output (const char *path)
{
  int fd;
  char buf[16];
  char *ptr;
  pid_t pid;

  fd = open (path, O_RDONLY);
  if (fd < 0)
    {
      zlog_err ("Can't open pid lock file %s (%s), continuing",
                path, safe_strerror(errno));
      return 0;
    }

  memset(buf, '\0', sizeof(buf));
  ptr = buf;
  read (fd, ptr, 16);
  pid = atoi(buf);

  close(fd);
  return pid;
}

#endif /* HAVE_FCNTL */
