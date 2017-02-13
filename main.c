/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
   vim: set autoindent expandtab shiftwidth=2 softtabstop=2 tabstop=2: */
/*
 * main.c
 *
 * Copyright (c) 2017 EMSTONE, All rights reserved.
 */

#ifdef _MSC_VER
#if _MSC_VER < 1900
#define inline __inline
#define snprintf _snprintf
#endif
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifdef _WIN32
#define strdup(x) _strdup(x)
#endif

#include "uvsocks.h"
#include <uv.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <locale.h>

/* Fake port to indicate that host field is really a path. */
#define PORT_STREAMLOCAL	-2
#define PATH_MAX_SUN 1024

typedef struct _fwdarg fwdarg;
struct _fwdarg
{
	char *arg;
	int   ispath;
};

extern char *optarg;
extern int optind;
extern int optreset;

static uv_loop_t  *main_loop;
static UvSocks    *main_uvsocks;
static uv_signal_t sigint;
static uv_signal_t sigterm;
static uv_signal_t sighup;

static void main_exit (void);

int
getopt (int         nargc,
        char *const nargv[],
        const char *ostr);

void
main_usage (void)
{
	fprintf (stderr,
          "usage: uvsocks [-R listen:port:host:port]\n"
          "               [-L listen:port:host:port]\n"
          "               [-l login_name]\n"
          "               [-a password]\n"
          "               [-p port]\n"
          "               [user:password@]hostname [command]\n"
          "\n"
          "example:\n"
          "  uvsocks -L 1234:192.168.0.231:8000 \\\n"
          "          -R 5824:192.168.0.231:8000 \\\n"
          "          user:password@192.168.0.15:1080\n"
          "  uvsocks -L 1234:192.168.0.231:8000 \\\n"
          "          -R 5824:192.168.0.231:8000 \\\n"
          "          192.168.0.15 -l user -a password -p 1080\n"
	        );
}

static int
main_parse_forward_field (char    **p,
                          fwdarg   *forward)
{
	char *ep, *cp = *p;
	int ispath = 0;

	if (*cp == '\0')
    {
		  *p = NULL;
		  return -1;	/* end of string */
	  }

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	if (*cp == '[')
    {
		  /* find matching ']' */
		  for (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++)
        {
			    if (*ep == '/')
				    ispath = 1;
		    }
		  /* no matching ']' or not at end of field. */
		  if (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			  return -1;
		  /* NUL terminate the field and advance p past the colon */
		  *ep++ = '\0';
		  if (*ep != '\0')
			  *ep++ = '\0';
		  forward->arg = cp + 1;
		  forward->ispath = ispath;
		  *p = ep;
		  return 0;
	  }

	for (cp = *p; *cp != '\0'; cp++)
    {
		  switch (*cp)
        {
		    case '\\':
			    memmove(cp, cp + 1, strlen(cp + 1) + 1);
			    if (*cp == '\0')
				    return -1;
			    break;
		    case '/':
			    ispath = 1;
			    break;
		    case ':':
			    *cp++ = '\0';
			    goto done;
		    }
	  }
done:
	forward->arg = *p;
	forward->ispath = ispath;
	*p = cp;
	return 0;
}

int
main_parse_forward (const char *forwardspec,
                    int         dynamicforward,
                    int         remoteforward,
                    char      **listen_host,
                    int        *listen_port,
                    char      **listen_path,
                    char      **remote_host,
                    int        *remote_port,
                    char      **remote_path)
{
	fwdarg forwardargs[4];
	char *p, *cp;
	int i;

	memset (forwardargs, 0, sizeof (forwardargs));

	cp = p = strdup (forwardspec);

	/* skip leading spaces */
	while (isspace ((unsigned char) *cp))
		cp++;

	for (i = 0; i < 4; ++i)
    {
		  if (main_parse_forward_field (&cp, &forwardargs[i]) != 0)
			  break;
	  }

	/* Check for trailing garbage */
	if (cp != NULL && *cp != '\0')
    i = 0;	/* failure */

	switch (i)
    {
	  case 1:
		  if (forwardargs[0].ispath)
        {
			    *listen_path = strdup (forwardargs[0].arg);
			    *listen_port = PORT_STREAMLOCAL;
		    }
      else
        {
			    *listen_host = NULL;
			    *listen_port = (int) strtol (forwardargs[0].arg, (char **) NULL, 10);
		    }
		  *remote_host = strdup ("socks");
		  break;
	  case 2:
		  if (forwardargs[0].ispath && forwardargs[1].ispath)
        {
			    *listen_path = strdup (forwardargs[0].arg);
			    *listen_port = PORT_STREAMLOCAL;
			    *remote_path = strdup (forwardargs[1].arg);
			    *remote_port = PORT_STREAMLOCAL;
		    }
      else if (forwardargs[1].ispath)
        {
			    *listen_host = NULL;
			    *listen_port = (int) strtol (forwardargs[0].arg, (char **) NULL, 10);
			    *remote_path = strdup (forwardargs[1].arg);
			    *remote_port = PORT_STREAMLOCAL;
		    }
      else
        {
			    *listen_host = strdup (forwardargs[0].arg);
			    *listen_port = (int) strtol (forwardargs[1].arg, (char **) NULL, 10);
			    *remote_host = strdup ("socks");
		    }
		  break;
	  case 3:
		  if (forwardargs[0].ispath)
        {
			    *listen_path = strdup (forwardargs[0].arg);
			    *listen_port = PORT_STREAMLOCAL;
			    *remote_host = strdup (forwardargs[1].arg);
			    *remote_port = (int) strtol (forwardargs[2].arg, (char **) NULL, 10);
		    }
      else if (forwardargs[2].ispath)
        {
			    *listen_host = strdup (forwardargs[0].arg);
			    *listen_port = (int) strtol (forwardargs[1].arg, (char **) NULL, 10);
			    *remote_path = strdup (forwardargs[2].arg);
			    *remote_port = PORT_STREAMLOCAL;
		    }
      else
        {
			    *listen_host = NULL;
			    *listen_port = (int) strtol (forwardargs[0].arg, (char **) NULL, 10);
			    *remote_host = strdup (forwardargs[1].arg);
			    *remote_port = (int) strtol (forwardargs[2].arg, (char **) NULL, 10);
		    }
		  break;
	  case 4:
		  *listen_host = strdup (forwardargs[0].arg);
		  *listen_port = (int)strtol (forwardargs[1].arg, (char **) NULL, 10);
		  *remote_host = strdup (forwardargs[2].arg);
		  *remote_port = (int)strtol (forwardargs[3].arg, (char **) NULL, 10);
		  break;
	  default:
		  i = 0; /* failure */
	  }

	free (p);

	if (dynamicforward)
    {
		  if (!(i == 1 || i == 2))
			  goto fail_free;
	  }
  else
    {
		  if (!(i == 3 || i == 4))
        {
			    if (*remote_path == NULL &&
			        *listen_path == NULL)
				    goto fail_free;
		    }
		  if (*remote_port <= 0 && *remote_path == NULL)
			  goto fail_free;
	  }

	if ((*listen_port < 0 && *listen_path == NULL) ||
	    (!remoteforward && *listen_port == 0))
		goto fail_free;
	if (*remote_host != NULL &&
      strlen (*remote_host) >= NI_MAXHOST)
		goto fail_free;
	/* XXX - if connecting to a remote socket, max sun len may not match this host */
	if (*remote_path != NULL &&
	    strlen (*remote_path) >= PATH_MAX_SUN)
		goto fail_free;
	if (*listen_host != NULL &&
	    strlen (*listen_host) >= NI_MAXHOST)
		goto fail_free;
	if (*listen_path != NULL &&
	    strlen (*listen_path) >= PATH_MAX_SUN)
		goto fail_free;

	return (i);

 fail_free:
	free (*remote_host);
	*remote_host = NULL;
	free (*remote_path);
	*remote_path = NULL;
	free (*listen_host);
	*listen_host = NULL;
	free (*listen_path);
	*listen_path = NULL;
	return (0);
}

static void
main_handle_signals (uv_signal_t *handle,
                     int          signum)
{
  fprintf (stderr, "main: signal[%d] received\n", signum);

  uv_stop (main_loop);
}

static void
main_setup (uv_loop_t *loop)
{
  uv_signal_init (loop, &sigint);
  uv_signal_start (&sigint, main_handle_signals, SIGINT);

  uv_signal_init (loop, &sigterm);
  uv_signal_start (&sigterm, main_handle_signals, SIGTERM);

  uv_signal_init (loop, &sighup);
  uv_signal_start (&sighup, main_handle_signals, SIGHUP);
}

static void
main_cleanup (void)
{
  uv_signal_stop (&sigint);
  uv_signal_stop (&sigterm);
  uv_signal_stop (&sighup);
}

static void
main_uvsocks_tunneled (UvSocks      *uvsocks,
                       UvSocksStatus status,
                       void         *data)
{
	fprintf (stderr,
				  "main_uvsocks_tunneled: \n");
}

static void
main_uvsocks_forwarded (UvSocks      *uvsocks,
                        char         *remote_host,
                        int           remote_port,
                        char         *listen_host,
                        int           listen_port,
                        void         *data)
{
	fprintf (stderr,
				  "forwarded: %s:%d -> %s:%d\n",
           listen_host,
           listen_port,
           remote_host,
           remote_port);
}

static int
main_tunnel (int    ac,
             char **av)
{
  int ret;
	int opt;
	char *p;
	char *cp;
  char *host;
  int port;
  char *user;
  char *password;
  char *listen_host;
  int listen_port;
  char *listen_path;
  char *remote_host;
  int remote_port;
  char *remote_path;

  ret = 0;
  host = NULL;
  port = 1080;
  user = NULL;
  password = NULL;

again:
  while ((opt = getopt (ac,
                        av,
                       "a:l:p:"
	                     "L:R:")) != -1)
  {
    listen_host = NULL;
    listen_port = -1;
    listen_path = NULL;
    remote_host = NULL;
    remote_port = -1;
    remote_path = NULL;

		switch (opt)
      {
		  case 'p':
			  port = (int) strtol (optarg, (char **) NULL, 10);
			  if (port <= 0)
          {
				    fprintf (stderr, "Bad port '%s'\n", optarg);
			    }
			  break;
		  case 'l':
			  user = strdup (optarg);
			  break;
		  case 'a':
			  password = strdup (optarg);
			  break;
		  case 'L':
			  if (main_parse_forward (optarg, 0, 0,
                                &listen_host,
                                &listen_port,
                                &listen_path,
                                &remote_host,
                                &remote_port,
                                &remote_path))
				  uvsocks_add_forward (main_uvsocks,
                               listen_host ? listen_host : "0.0.0.0",
                               listen_port,
                               remote_host ? remote_host : "0.0.0.0",
                               remote_port,
                               main_uvsocks_forwarded, NULL);
			  else {
				  fprintf (stderr,
				          "Bad forwarding specification '%s'\n",
				           optarg);
			  }
			  break;
		  case 'R':
			  if (main_parse_forward (optarg, 0, 1,
                                &listen_host,
                                &listen_port,
                                &listen_path,
                                &remote_host,
                                &remote_port,
                                &remote_path))
          uvsocks_add_reverse_forward (main_uvsocks,
                                       listen_host ? listen_host : "0.0.0.0",
                                       listen_port,
                                       remote_host ? remote_host : "0.0.0.0",
                                       remote_port,
                                       main_uvsocks_forwarded, NULL);
        else
          {
				    fprintf (stderr,
				            "Bad reverse forwarding specification "
				            "'%s'\n",
                     optarg);
			    }
			  break;
		  default:
			  main_usage ();
        break;
		  }

    free (listen_host);
    free (listen_path);
    free (remote_host);
    free (remote_path);
  }
	
  ac -= optind;
	av += optind;

	if (ac > 0)
    {
		  if (strrchr(*av, '@'))
        {
			    p = strdup (*av);
			    cp = strrchr(p, '@');
			    if (cp == NULL || cp == p)
				    main_usage();
			    user = p;
			    *cp = '\0';
			    host = strdup (++cp);

          if (strrchr(user, ':'))
            {
              cp = strrchr(user, ':');
			        user = p;
			        *cp = '\0';
			        password = strdup (++cp);
            }
		    }
      else
			  host = strdup (*av);

      if (strrchr(host, ':'))
        {
          p = host;
          cp = strrchr(host, ':');
			    host = p;
			    *cp = '\0';
			    port = (int) strtol (++cp, (char **) NULL, 10);
			  if (port <= 0)
          {
				    fprintf (stderr, "Bad port '%s'\n", optarg);
			    }
        }

		  if (ac > 1)
        {
			    optind = optreset = 1;
			    goto again;
		    }
		  ac--;
      av++;
	  }

	/* Check that we got a host name. */
  if (!host)
    {
      main_usage();
      ret = 1;
    }
  else
    ret =  uvsocks_tunnel (main_uvsocks,
                           host ? host : "",
                           port,
                           user ? user : "",
                           password ? password : "",
                           main_uvsocks_tunneled,
                           main_uvsocks);

  free (host);
  free (user);
  free (password);
  return ret;
}

void
main_exit (void)
{
  main_cleanup ();
  uvsocks_free (main_uvsocks);
}

int
main (int    argc,
      char **argv)
{
  /* Some uv_fs_*() functions use WIN32 API initialized at uv__once_init() in
     WIN32. Call uv_hrtime() to execute uv_once_init() internally. */
  uv_hrtime ();
  main_loop = uv_default_loop ();
  main_setup (main_loop);
  main_uvsocks = uvsocks_new (main_loop);
  if (main_tunnel (argc, argv))
    goto fail;
  uv_run (main_loop, UV_RUN_DEFAULT);
fail:
  main_exit ();
  uv_loop_close (main_loop);
  return EXIT_SUCCESS;
}
