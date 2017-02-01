/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*-
   vim: set autoindent expandtab shiftwidth=2 softtabstop=2 tabstop=2: */
/*
 * uvsocks.h
 *
 * Copyright (c) 2017 EMSTONE, All rights reserved.
 */

#ifndef __UVSOCKS_H__
#define __UVSOCKS_H__

typedef enum _UvSocksStatus
{
  UVSOCKS_OK = 0,
  UVSOCKS_ERROR_POLL_REMOTE_READ,
  UVSOCKS_ERROR_POLL_REMOTE_READ_START,
  UVSOCKS_ERROR_POLL_LOCAL_READ,
  UVSOCKS_ERROR_POLL_LOCAL_READ_START,
  UVSOCKS_ERROR_POLL_LOCAL_RECV,
  UVSOCKS_ERROR_POLL_LOCAL_SEND,
  UVSOCKS_ERROR_POLL_REMOTE_RECV,
  UVSOCKS_ERROR_POLL_REMOTE_SEND,
  UVSOCKS_ERROR_LOCAL_SERVER,
  UVSOCKS_ERROR_AUTH,
  UVSOCKS_ERROR_SOCKET,
  UVSOCKS_ERROR_HANDSHAKE,
  UVSOCKS_ERROR_CONNECT,
  UVSOCKS_ERROR_FORWARD,
  UVSOCKS_ERROR_DNS_RESOLVE,
  UVSOCKS_ERROR_DNS_ADDRINFO,
} UvSocksStatus;

typedef struct _UvSocks UvSocks;

UvSocks *
uvsocks_new (void);

void
uvsocks_free (UvSocks *uvsocks);

typedef void (*UvSocksForwardFunc) (UvSocks      *uvsocks,
                                    char         *remote_host,
                                    int           remote_port,
                                    char         *listen_host,
                                    int           listen_port,
                                    void         *data);

void
uvsocks_add_forward (UvSocks           *uvsocks,
                     char              *listen_host,
                     int                listen_port,
                     char              *listen_path,
                     char              *remote_host,
                     int                remote_port,
                     char              *connect_path,
                     UvSocksForwardFunc callback_func,
                     void              *callback_data);

void
uvsocks_add_reverse_forward (UvSocks           *uvsocks,
                             char              *listen_host,
                             int                listen_port,
                             char              *listen_path,
                             char              *remote_host,
                             int                remote_port,
                             char              *connect_path,
                             UvSocksForwardFunc callback_func,
                             void              *callback_data);

typedef void (*UvSocksTunnelFunc) (UvSocks      *uvsocks,
                                   UvSocksStatus status,
                                   void         *data);
int
uvsocks_tunnel (UvSocks           *uvsocks,
                char              *host,
                int                port,
                char              *user,
                char              *password,
                UvSocksTunnelFunc  callback_func,
                void              *callback_data);

#endif /* __UVSOCKS_H__ */