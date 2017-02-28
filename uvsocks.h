/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
   vim: set autoindent expandtab shiftwidth=2 softtabstop=2 tabstop=2: */

#ifndef __UVSOCKS_H__
#define __UVSOCKS_H__

typedef struct _UvSocks UvSocks;

typedef enum _UvSocksNotify UvSocksNotify;
enum _UvSocksNotify
{
  UVSOCKS_OK                            = 0,
  UVSOCKS_OK_TCP_SERVER                 = 1,
  UVSOCKS_OK_TCP_NEW_CONNECT            = 2,
  UVSOCKS_OK_TCP_CONNECTED              = 3,
  UVSOCKS_OK_SOCKS_CONNECT              = 4,
  UVSOCKS_OK_SOCKS_BIND                 = 5,
  UVSOCKS_ERROR                         = 1001,
  UVSOCKS_ERROR_TCP_SERVER              = 1002,
  UVSOCKS_ERROR_TCP_PORT                = 1003,
  UVSOCKS_ERROR_TCP_BIND                = 1004,
  UVSOCKS_ERROR_TCP_LISTEN              = 1005,
  UVSOCKS_ERROR_TCP_NEW_CONNECT         = 1006,
  UVSOCKS_ERROR_TCP_CREATE_SESSION      = 1007,
  UVSOCKS_ERROR_TCP_ACCEPT              = 1008,
  UVSOCKS_ERROR_DNS_RESOLVED            = 1009,
  UVSOCKS_ERROR_DNS_ADDRINFO            = 1010,
  UVSOCKS_ERROR_TCP_CONNECTED           = 1011,
  UVSOCKS_ERROR_TCP_READ_START          = 1012,
  UVSOCKS_ERROR_TCP_SOCKS_READ          = 1013,
  UVSOCKS_ERROR_TCP_LOCAL_READ          = 1014,
  UVSOCKS_ERROR_SOCKS_HANDSHAKE         = 1015,
  UVSOCKS_ERROR_SOCKS_AUTHENTICATION    = 1016,
  UVSOCKS_ERROR_SOCKS_COMMAND           = 1017,
  UVSOCKS_ERROR_SOCKS_CMD_BIND          = 1018,
  UVSOCKS_ERROR_TCP_INSUFFICIENT_BUFFER = 1019,
};

typedef struct _UvSocksParam UvSocksParam;
struct _UvSocksParam
{
  int    is_forward;
  char   destination_host[64];
  int    destination_port;
  char   listen_host[64];
  int    listen_port;
};

typedef void (*UvSocksNotifyFunc) (UvSocks       *uvsocks,
                                   UvSocksNotify  notify,
                                   UvSocksParam  *param,
                                   void          *data);

UvSocks *
uvsocks_new (void              *uv_loop,
             const char        *host,
             int                port,
             const char        *user,
             const char        *password,
             int                n_params,
             UvSocksParam      *params,
             UvSocksNotifyFunc  callback_func,
             void              *callback_data);

int
uvsocks_run (UvSocks *uvsocks);

void
uvsocks_free (UvSocks *uvsocks);

char *
uvsocks_get_notify (UvSocksNotify notify);

#endif /* __UVSOCKS_H__ */