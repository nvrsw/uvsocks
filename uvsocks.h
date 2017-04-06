/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
   vim: set autoindent expandtab shiftwidth=2 softtabstop=2 tabstop=2: */

#ifndef __UVSOCKS_H__
#define __UVSOCKS_H__

typedef struct _UvSocks UvSocks;

typedef enum _UvSocksStatus UvSocksStatus;
enum _UvSocksStatus
{
  UVSOCKS_OK                            = 0,
  UVSOCKS_OK_TCP_LOCAL_SERVER           = 0x0001,
  UVSOCKS_OK_TCP_NEW_CONNECT            = 0x0002,
  UVSOCKS_OK_TCP_CONNECTED              = 0x0003,
  UVSOCKS_OK_SOCKS_CONNECT              = 0x0004,
  UVSOCKS_OK_SOCKS_BIND                 = 0x0005,
  UVSOCKS_ERROR                         = 0x1001,
  UVSOCKS_ERROR_PARAMETERS              = 0x1002,
  UVSOCKS_ERROR_TCP_LOCAL_SERVER        = 0x1003,
  UVSOCKS_ERROR_TCP_PORT                = 0x1004,
  UVSOCKS_ERROR_TCP_BIND                = 0x1005,
  UVSOCKS_ERROR_TCP_LISTEN              = 0x1006,
  UVSOCKS_ERROR_TCP_NEW_CONNECT         = 0x1007,
  UVSOCKS_ERROR_TCP_CREATE_SESSION      = 0x1008,
  UVSOCKS_ERROR_TCP_ACCEPT              = 0x1009,
  UVSOCKS_ERROR_DNS_RESOLVED            = 0x1010,
  UVSOCKS_ERROR_DNS_ADDRINFO            = 0x1011,
  UVSOCKS_ERROR_TCP_CONNECTED           = 0x1012,
  UVSOCKS_ERROR_TCP_READ_START          = 0x1013,
  UVSOCKS_ERROR_TCP_SOCKS_READ          = 0x1014,
  UVSOCKS_ERROR_TCP_LOCAL_READ          = 0x1015,
  UVSOCKS_ERROR_SOCKS_HANDSHAKE         = 0x1016,
  UVSOCKS_ERROR_SOCKS_AUTHENTICATION    = 0x1017,
  UVSOCKS_ERROR_SOCKS_CMD_BIND          = 0x1018,
  UVSOCKS_ERROR_SOCKS_COMMAND           = 0x1019, /* must be the last */
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

void
uvsocks_run (UvSocks *uvsocks);

void
uvsocks_free (UvSocks *uvsocks);

const char *
uvsocks_get_status_string (UvSocksStatus status);

#endif /* __UVSOCKS_H__ */