/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
   vim: set autoindent expandtab shiftwidth=2 softtabstop=2 tabstop=2: */

#ifndef __UVSOCKS_H__
#define __UVSOCKS_H__

typedef struct _UvSocks UvSocks;

typedef enum _UvSocksStatus UvSocksStatus;
enum _UvSocksStatus
{
  UVSOCKS_OK                            = 0,
  UVSOCKS_OK_TCP_LOCAL_SERVER           = 1,
  UVSOCKS_OK_TCP_NEW_CONNECT            = 2,
  UVSOCKS_OK_TCP_CONNECTED              = 3,
  UVSOCKS_OK_SOCKS_CONNECT              = 4,
  UVSOCKS_OK_SOCKS_BIND                 = 5,
  UVSOCKS_ERROR                         = 1001,
  UVSOCKS_ERROR_PARAMETERS              = 1002,
  UVSOCKS_ERROR_TCP_LOCAL_SERVER        = 1003,
  UVSOCKS_ERROR_TCP_PORT                = 1004,
  UVSOCKS_ERROR_TCP_BIND                = 1005,
  UVSOCKS_ERROR_TCP_LISTEN              = 1006,
  UVSOCKS_ERROR_TCP_NEW_CONNECT         = 1007,
  UVSOCKS_ERROR_TCP_CREATE_SESSION      = 1008,
  UVSOCKS_ERROR_TCP_ACCEPT              = 1009,
  UVSOCKS_ERROR_DNS_RESOLVED            = 1010,
  UVSOCKS_ERROR_DNS_ADDRINFO            = 1011,
  UVSOCKS_ERROR_TCP_CONNECTED           = 1012,
  UVSOCKS_ERROR_TCP_READ_START          = 1013,
  UVSOCKS_ERROR_TCP_SOCKS_READ          = 1014,
  UVSOCKS_ERROR_TCP_LOCAL_READ          = 1015,
  UVSOCKS_ERROR_SOCKS_HANDSHAKE         = 1016,
  UVSOCKS_ERROR_SOCKS_AUTHENTICATION    = 1017,
  UVSOCKS_ERROR_SOCKS_COMMAND           = 1018,
  UVSOCKS_ERROR_SOCKS_CMD_BIND          = 1019,
  UVSOCKS_ERROR_TCP_INSUFFICIENT_BUFFER = 1020,
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

typedef void (*UvSocksStatusFunc) (UvSocks       *uvsocks,
                                   UvSocksStatus  status,
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
             UvSocksStatusFunc  callback_func,
             void              *callback_data);

int
uvsocks_run (UvSocks *uvsocks);

void
uvsocks_free (UvSocks *uvsocks);

const char *
uvsocks_get_status_string (UvSocksStatus status);

#endif /* __UVSOCKS_H__ */