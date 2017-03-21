/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
   vim: set autoindent expandtab shiftwidth=2 softtabstop=2 tabstop=2: */

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

extern char *optarg;
extern int optind;
extern int optreset;

#define UVSOCKS_PARAM_MAX 64

static uv_loop_t   *main_loop;
static UvSocks     *main_uvsocks;
static char         main_host[64];
static int          main_port;
static char         main_user[64];
static char         main_password[64];
static int          main_n_params;
static UvSocksParam main_params[UVSOCKS_PARAM_MAX];

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
          "usage: uvsocks [-R listen:port:destination:port]\n"
          "               [-L listen:port:destination:port]\n"
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

static void
main_handle_signals (uv_signal_t *handle,
                     int          signum)
{
  fprintf (stderr, "main: signal[%d] received\n", signum);

  uvsocks_free (main_uvsocks);
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
main_uvsocks_notify (UvSocks       *uvsocks,
                     UvSocksStatus  status,
                     UvSocksParam  *param,
                     void          *data)
{
	fprintf (stderr,
				  "main[%s] %s:%d -> %s:%d\n",
           uvsocks_get_status_string (status),
           param->destination_host,
           param->destination_port,
           param->listen_host,
           param->listen_port);
}

char **
main_split_string (const char *string,
                   const char *delimiter,
                   int        *n_strings)
{
  const char *str;
  char      **strings;
  size_t      delimiter_len;
  int         n;

  if (n_strings)
    *n_strings = 0;

  if (!string || !delimiter)
    return NULL;

  delimiter_len = strlen (delimiter);

  n = 1;
  for (str = string; *str; n++)
    {
      char *s;

      s = strstr (str, delimiter);
      if (!s)
        break;
      str = s + delimiter_len;
    }

  strings = calloc (n + 1, sizeof (char *));

  n = 0;
  str = string;
  do
    {
      char *s;
      char *a;
      size_t len;

      s = strstr (str, delimiter);
      if (s)
        len = s - str;
      else
        len = strlen (str);

      if (s || len > 0)
        {
          a = malloc (len + 1);
          if (len > 0)
            memcpy (a, str, len);
          a[len] = '\0';
          strings[n] = a;
          n++;
        }

      if (!s)
        break;
      str = s + delimiter_len;
    }
  while (*str);

  if (n_strings)
    *n_strings = n;

  return strings;
}

void
main_free_strings (char **strings)
{
  int n;

  if (!strings)
    return;

  for (n = 0; strings[n]; n++)
    free (strings[n]);
  free (strings);
}

static int
main_get_param (int    ac,
                char **av)
{
	int opt;

  main_n_params = 0;
  main_host[0] = '\0';
  main_port = 1080;
  main_user[0] = '\0';
  main_password[0] = '\0';

again:
  while ((opt = getopt (ac,
                        av,
                       "a:l:p:"
	                     "L:R:")) != -1)
  {
		switch (opt)
      {
		  case 'p':
			  main_port = (int) strtol (optarg, (char **) NULL, 10);
			  break;
		  case 'l':
        strcpy (main_user, optarg);
			  break;
		  case 'a':
			  strcpy (main_password, optarg);
			  break;
		  case 'L':
		  case 'R':
        {
          char **strs;
          int n;

          n = 0;
          strs = main_split_string (optarg, ":", &n);
          if (n > 0)
            {
              strcpy (main_params[main_n_params].listen_host,
                      (n >= 4) ? strs[n-4] : "0.0.0.0");
              main_params[main_n_params].listen_port =
                (int) strtol ((n >= 3) ? strs[n-3] : "0", (char **) NULL, 10);
              strcpy (main_params[main_n_params].destination_host,
                      (n >= 2) ? strs[n-2] : "0.0.0.0");
              main_params[main_n_params].destination_port =
                (int) strtol ((n >= 1) ? strs[n-1] : "0", (char **) NULL, 10);

              main_params[main_n_params].is_forward = (opt == 'L');
              main_n_params++;
            }
          main_free_strings (strs);
        }
			  break;
		  }
  }
  ac -= optind;
	av += optind;
	if (ac > 0)
    {
      char *socks_host;
      char **socks_hosts;
      int n_socks_hosts;

      n_socks_hosts = 0;
      socks_hosts = main_split_string (*av, "@", &n_socks_hosts);
      if (n_socks_hosts > 1)
        {
          char **user;
          int user_n;

          user_n = 0;
          user = main_split_string (socks_hosts[0], ":", &user_n);
          if (user_n > 1)
            {
                strcpy (main_user, user[0]);
                strcpy (main_password, user[1]);
            }
          else
            strcpy (main_user, user[0]);

          main_free_strings (user);
          socks_host = socks_hosts[1];
        }
      else
        socks_host = socks_hosts[0];

      if (socks_host)
        {
          char **host;
          int host_n;

          host_n = 0;
          host = main_split_string (socks_host, ":", &host_n);
          if (host_n > 1)
            {
                strcpy (main_host, host[0]);
                main_port = (int) strtol (host[1], (char **) NULL, 10);
            }
          else
            strcpy (main_host, host[0]);

          main_free_strings (host);
        }

      main_free_strings (socks_hosts);

		  if (ac > 1)
        {
			    optind = optreset = 1;
			    goto again;
		    }
		  ac--;
      av++;
	  }

  if (main_n_params == 0 ||
      main_port <= 0 ||
      main_user == '\0' ||
      main_password == '\0')
    {
      main_usage ();
      return 1;
    }

  return 0;
}

void
main_exit (void)
{
  main_cleanup ();
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

  if (main_get_param (argc, argv))
    goto fail;

  main_uvsocks = uvsocks_new (NULL,
                              main_host,
                              main_port,
                              main_user,
                              main_password,
                              main_n_params,
                              main_params,
                              main_uvsocks_notify,
                              NULL);
  if (!main_uvsocks)
    goto fail;

  uvsocks_run (main_uvsocks);

  uv_run (main_loop, UV_RUN_DEFAULT);

fail:

  main_exit ();
  uv_loop_close (main_loop);

  return EXIT_SUCCESS;
}
