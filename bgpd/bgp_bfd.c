/* Show BFD neighbor
   Copyright (C) 2018 6WIND

This file is part of GNU Quagga.

GNU Quagga is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Quagga is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Quagga; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include <sys/un.h>

#include "command.h"
#include "log.h"
#include "memory.h"
#include "stream.h"

#include "bgpd/bgpd.h"

#define VTYSH_BFDD   0x200
#define BGP_BFD_BUFSIZ 4096

/* VTY shell client structure. */
struct vtysh_client
{
  int fd;
  const char *name;
  int flag;
  const char *path;
} vtysh_client_bfdd =
  { .fd = -1, .name = "bfdd", .flag = VTYSH_BFDD, .path = BFD_VTYSH_PATH};

/* Making connection to protocol daemon. */
static int
vtysh_connect (struct vtysh_client *vclient)
{
  int ret;
  int sock, len;
  struct sockaddr_un addr;
  struct stat s_stat;

  /* Stat socket to see if we have permission to access it. */
  ret = stat (vclient->path, &s_stat);
  if (ret < 0 && errno != ENOENT)
    {
      fprintf  (stderr, "vtysh_connect(%s): stat = %s\n",
		vclient->path, safe_strerror(errno));
      exit(1);
    }

  if (ret >= 0)
    {
      if (! S_ISSOCK(s_stat.st_mode))
	{
	  fprintf (stderr, "vtysh_connect(%s): Not a socket\n",
		   vclient->path);
	  exit (1);
	}
    }

  sock = socket (AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0)
    {
#ifdef DEBUG
      fprintf(stderr, "vtysh_connect(%s): socket = %s\n", vclient->path,
	      safe_strerror(errno));
#endif /* DEBUG */
      return -1;
    }

  memset (&addr, 0, sizeof (struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  strncpy (addr.sun_path, vclient->path, strlen (vclient->path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
  len = addr.sun_len = SUN_LEN(&addr);
#else
  len = sizeof (addr.sun_family) + strlen (addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

  ret = connect (sock, (struct sockaddr *) &addr, len);
  if (ret < 0)
    {
#ifdef DEBUG
      fprintf(stderr, "vtysh_connect(%s): connect = %s\n", vclient->path,
	      safe_strerror(errno));
#endif /* DEBUG */
      close (sock);
      return -1;
    }
  vclient->fd = sock;

  return 0;
}

static void
vclient_close (struct vtysh_client *vclient)
{
  if (vclient->fd >= 0)
    {
      fprintf(stderr,
	      "Warning: closing connection to %s because of an I/O error!\n",
	      vclient->name);
      close (vclient->fd);
      vclient->fd = -1;
    }
}

#define ERR_WHERE_STRING "vtysh(): vtysh_client_execute(): "
static int
vtysh_client_execute (struct vtysh_client *vclient, const char *line, struct vty *vty)
{
  int ret;
  char *buf;
  size_t bufsz;
  char *pbuf;
  size_t left;
  char *eoln;
  int nbytes;
  int i;
  int readln;
  int numnulls = 0;
  char *begin, *p;

  if (vclient->fd < 0)
    return CMD_SUCCESS;

  ret = write (vclient->fd, line, strlen (line) + 1);
  if (ret <= 0)
    {
      vclient_close (vclient);
      return CMD_SUCCESS;
    }

  /* Allow enough room for buffer to read more than a few pages from socket. */
  bufsz = 5 * getpagesize() + 1;
  buf = XMALLOC(MTYPE_TMP, bufsz);
  memset(buf, 0, bufsz);
  pbuf = buf;

  while (1)
    {
      if (pbuf >= ((buf + bufsz) -1))
	{
	  vty_out (vty, ERR_WHERE_STRING \
		   "warning - pbuf beyond buffer end.%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      readln = (buf + bufsz) - pbuf - 1;
      nbytes = read (vclient->fd, pbuf, readln);

      if (nbytes <= 0)
	{

	  if (errno == EINTR)
	    continue;

	  vty_out (vty, ERR_WHERE_STRING "(%u)%s", errno, VTY_NEWLINE);
	  perror("");

	  if (errno == EAGAIN || errno == EIO)
	    continue;

	  vclient_close (vclient);
	  XFREE(MTYPE_TMP, buf);
	  return CMD_SUCCESS;
	}
      /* If we have already seen 3 nulls, then current byte is ret code */
      if ((numnulls == 3) && (nbytes == 1))
        {
           ret = pbuf[0];
           break;
        }

      pbuf[nbytes] = '\0';

      begin = p = pbuf;
      while (*p != '\0')
        {
          if (*p == '\n')
	    {
	      *p++ = '\0';
	      vty_out (vty, "%s%s", begin, VTY_NEWLINE);
	      begin = p;
	    }
          else
	    {
	      p++;
	    }
        }

       /* At max look last four bytes */
       if (nbytes >= 4)
       {
         i = nbytes - 4;
         numnulls = 0;
       }
       else
         i = 0;

       /* Count the numnulls */
       while (i < nbytes && numnulls <3)
       {
         if (pbuf[i++] == '\0')
            numnulls++;
         else
            numnulls = 0;
       }
       /* We might have seen 3 consecutive nulls so store the ret code before updating pbuf*/
       ret = pbuf[nbytes-1];
       pbuf += nbytes;

       /* See if a line exists in buffer, if so parse and consume it, and
        * reset read position. If 3 nulls has been encountered consume the buffer before
        * next read.
        */
       if (((eoln = strrchr(buf, '\n')) == NULL) && (numnulls<3))
         continue;

       if (eoln >= ((buf + bufsz) - 1))
       {
          vty_out (vty, ERR_WHERE_STRING \
                   "warning - eoln beyond buffer end.%s", VTY_NEWLINE);
       }

       eoln++;
       left = (size_t)(buf + bufsz - eoln);
       /*
        * This check is required since when a config line split between two consecutive reads,
        * then buf will have first half of config line and current read will bring rest of the
        * line. So in this case eoln will be 1 here, hence calculation of left will be wrong.
        * In this case we don't need to do memmove, because we have already seen 3 nulls.
        */
       if(left < bufsz)
         memmove(buf, eoln, left);

       buf[bufsz-1] = '\0';
       pbuf = buf + strlen(buf);
       /* got 3 or more trailing NULs? */
       if ((numnulls >=3) && (i < nbytes))
       {
          break;
       }
    }

  XFREE(MTYPE_TMP, buf);
  return ret;
}

DEFUN (show_bgp_bfd_neighbors,
       show_bgp_bfd_neighbors_cmd,
       "show bgp bfd neighbors",
       SHOW_STR
       BGP_STR
       BFD_STR
       "BFD neighbors\n")
{
  vtysh_connect (&vtysh_client_bfdd);
  vtysh_client_execute (&vtysh_client_bfdd, "show bfd neighbors", vty);
  vclient_close (&vtysh_client_bfdd);

  return CMD_SUCCESS;
}

DEFUN (show_bgp_bfd_neighbors_peer,
       show_bgp_bfd_neighbors_peer_cmd,
       "show bgp bfd neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       BFD_STR
       "BFD neighbors\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")
{
  char cmd[BGP_BFD_BUFSIZ];

  snprintf(cmd, sizeof(cmd), "show bfd neighbors %s", argv[0]);
  vtysh_connect (&vtysh_client_bfdd);
  vtysh_client_execute (&vtysh_client_bfdd, cmd, vty);
  vclient_close (&vtysh_client_bfdd);

  return CMD_SUCCESS;
}

DEFUN (show_bgp_bfd_neighbors_details,
       show_bgp_bfd_neighbors_details_cmd,
       "show bgp bfd neighbors details",
       SHOW_STR
       BGP_STR
       BFD_STR
       "BFD neighbors\n")
{
  vtysh_connect (&vtysh_client_bfdd);
  vtysh_client_execute (&vtysh_client_bfdd, "show bfd neighbors details", vty);
  vclient_close (&vtysh_client_bfdd);

  return CMD_SUCCESS;
}

DEFUN (show_bgp_bfd_neighbors_peer_details,
       show_bgp_bfd_neighbors_peer_details_cmd,
       "show bgp bfd neighbors (A.B.C.D|X:X::X:X) details",
       SHOW_STR
       BGP_STR
       BFD_STR
       "BFD neighbors\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")
{
  char cmd[BGP_BFD_BUFSIZ];

  snprintf(cmd, sizeof(cmd), "show bfd neighbors %s details", argv[0]);
  vtysh_connect (&vtysh_client_bfdd);
  vtysh_client_execute (&vtysh_client_bfdd, cmd, vty);
  vclient_close (&vtysh_client_bfdd);

  return CMD_SUCCESS;
}


DEFUN (show_bgp_bfd_global_config,
       show_bgp_bfd_global_config_cmd,
       "show bgp bfd global-config",
       SHOW_STR
       BGP_STR
       BFD_STR
       "Show BFD global config\n")
{
  char cmd[BGP_BFD_BUFSIZ];

  snprintf(cmd, sizeof(cmd), "show bfd global-config");
  bgp_vtysh_connect (&vtysh_client_bfdd);
  bgp_vtysh_client_execute (&vtysh_client_bfdd, cmd, vty);
  bgp_vclient_close (&vtysh_client_bfdd);

  return CMD_SUCCESS;
}

void
bgp_bfd_init (void)
{
  install_element (VIEW_NODE, &show_bgp_bfd_neighbors_cmd);
  install_element (ENABLE_NODE, &show_bgp_bfd_neighbors_cmd);
  install_element (VIEW_NODE, &show_bgp_bfd_neighbors_peer_cmd);
  install_element (ENABLE_NODE, &show_bgp_bfd_neighbors_peer_cmd);
  install_element (VIEW_NODE, &show_bgp_bfd_neighbors_details_cmd);
  install_element (ENABLE_NODE, &show_bgp_bfd_neighbors_details_cmd);
  install_element (VIEW_NODE, &show_bgp_bfd_neighbors_peer_details_cmd);
  install_element (ENABLE_NODE, &show_bgp_bfd_neighbors_peer_details_cmd);
  install_element (VIEW_NODE, &show_bgp_bfd_global_config_cmd);
  install_element (ENABLE_NODE, &show_bgp_bfd_global_config_cmd);
}
