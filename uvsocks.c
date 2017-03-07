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

#ifdef _WIN32
#define strlcpy(x, y, z) strncpy_s((x), (z), (y), _TRUNCATE)
#endif

#include "uvsocks.h"
#include "aqueue.h"
#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <limits.h>

#ifdef linux
#include <sys/prctl.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#define container_of(ptr, type, member) (type *)((char *)ptr - offsetof (type, member))
#endif

#define UVSOCKS_BUF_MAX (1024 * 512)

#ifndef UV_BUF_LEN
#ifdef _WIN32
#define UV_BUF_LEN(x) ((ULONG)(x))
#else
#define UV_BUF_LEN(x) ((size_t)(x))
#endif
#endif

typedef enum _UvSocksVersion
{
  UVSOCKS_VER_5       = 0x05,
} UvSocksVersion;

typedef enum _UvSocksAuthMethod
{
  UVSOCKS_AUTH_NONE   = 0x00,
  UVSOCKS_AUTH_GSSAPI = 0x01,
  UVSOCKS_AUTH_PASSWD = 0x02,
} UvSocksAuthMethod;

typedef enum _UvSocksAuthResult
{
  UVSOCKS_AUTH_ALLOW = 0x00,
  UVSOCKS_AUTH_DENY  = 0x01,
} UvSocksAuthResult;

typedef enum _UvSocksAddrType
{
  UVSOCKS_ADDR_TYPE_IPV4 = 0x01,
  UVSOCKS_ADDR_TYPE_HOST = 0x03,
  UVSOCKS_ADDR_TYPE_IPV6 = 0x04,
} UvSocksAddrType;

typedef enum _UvSocksCmd
{
  UVSOCKS_CMD_CONNECT       = 0x01,
  UVSOCKS_CMD_BIND          = 0x02,
  UVSOCKS_CMD_UDP_ASSOCIATE = 0x03,
} UvSocksCmd;

typedef enum _UvSocksStage
{
  UVSOCKS_STAGE_NONE                = 0x00,
  UVSOCKS_STAGE_HANDSHAKE           = 0x01,
  UVSOCKS_STAGE_AUTHENTICATE        = 0x02,
  UVSOCKS_STAGE_ESTABLISH           = 0x03,
  UVSOCKS_STAGE_BIND                = 0x04,
  UVSOCKS_STAGE_TUNNEL              = 0x05,
} UvSocksStage;

#define UVSOCKS_SESSION_MAX           5

typedef struct _UvSocksTunnel UvSocksTunnel;
typedef struct _UvSocksSession UvSocksSession;
typedef struct _UvSocksSessionLink UvSocksSessionLink;

typedef void (*UvSocksDnsResolveFunc) (UvSocksSessionLink *link,
                                       struct addrinfo    *resolved);

typedef struct _UvSocksDnsResolve UvSocksDnsResolve;
struct _UvSocksDnsResolve
{
  uv_getaddrinfo_t      getaddrinfo;
  UvSocksDnsResolveFunc func;
  void                 *data;
};

struct _UvSocksSessionLink
{
  UvSocksSession       *session;

  uv_tcp_t             *read_tcp;
  char                  read_buf[UVSOCKS_BUF_MAX];
  size_t                read_buf_len;
  UvSocksSessionLink   *write_link;
  uv_write_t            write_req;

  UvSocksDnsResolve     dns_resolve;
};

struct _UvSocksSession
{
  UvSocksTunnel         *tunnel;
  UvSocksStage           stage;
  UvSocksSessionLink     socks;
  UvSocksSessionLink     local;
};

struct _UvSocksTunnel
{
  UvSocks               *uvsocks;
  UvSocksParam           param;
  uv_tcp_t              *listen_tcp;
  int                    n_sessions;
  UvSocksSession         sessions[UVSOCKS_SESSION_MAX];
};

struct _UvSocks
{
  int                    self_loop;
  uv_loop_t             *loop;
  AQueue                *queue;
  uv_async_t             async;
  uv_thread_t            thread;

  char                   host[64];
  int                    port;
  char                   user[64];
  char                   password[64];
  int                    n_tunnels;
  UvSocksTunnel         *tunnels;

  UvSocksStatusFunc      callback_func;
  void                  *callback_data;
};

typedef void (*UvSocksFunc) (UvSocks *uvsocks,
                             void    *data);

typedef struct _UvSocksMessage UvSocksMessage;
struct _UvSocksMessage
{
  UvSocksFunc   func;
  void         *data;
  void        (*destroy_data) (void *data);
};

typedef struct _UvSocksPacketReq UvSocksPacketReq;
struct _UvSocksPacketReq
{
  uv_write_t   req;
  uv_buf_t     buf;
  UvSocksStage stage;
};


static void
uvsocks_read (uv_stream_t    *stream,
              ssize_t         nread,
              const uv_buf_t *buf);

static void
uvsocks_receive_async (uv_async_t *handle)
{
  UvSocks *uvsocks = handle->data;

  while (1)
    {
      UvSocksMessage *msg;

      msg = aqueue_try_pop (uvsocks->queue);
      if (!msg)
        break;

      msg->func (uvsocks, msg->data);

      if (msg->destroy_data)
        msg->destroy_data (msg->data);
      free (msg);
    }
}

static void
uvsocks_send_async (UvSocks      *uvsocks,
                    UvSocksFunc   func,
                    void         *data,
                    void        (*destroy_data) (void *data))
{
  UvSocksMessage *msg;

  msg = malloc (sizeof (*msg));
  if (!msg)
    return;

  msg->func = func;
  msg->data = data;
  msg->destroy_data = destroy_data;
  aqueue_push (uvsocks->queue, msg);
  uv_async_send (&uvsocks->async);
}

static void
uvsocks_thread_main (void *arg)
{
  UvSocks *uvsocks = arg;

  uv_run (uvsocks->loop, UV_RUN_DEFAULT);
}

UvSocks *
uvsocks_new (void              *uv_loop,
             const char        *host,
             int                port,
             const char        *user,
             const char        *password,
             int                n_params,
             UvSocksParam      *params,
             UvSocksStatusFunc  callback_func,
             void              *callback_data)
{
  UvSocks *uvsocks;
  UvSocksTunnel *tunnels;
  int i;

  if (port < 0 || port > 65535)
    goto fail_parameter;

  if (host == NULL || user == NULL || password == NULL)
    goto fail_parameter;

  if (n_params <= 0)
    goto fail_parameter;

  for (i = 0; i < n_params; i++)
    {
      if (params[i].destination_port < 0 ||
          params[i].destination_port > 65535 ||
          params[i].listen_port < 0 ||
          params[i].listen_port > 65535)
        goto fail_parameter;

      if (params[i].destination_host == NULL ||
          params[i].listen_host == NULL)
        goto fail_parameter;
    }

  uvsocks = calloc (sizeof (UvSocks), 1);
  if (!uvsocks)
    return NULL;

  tunnels = calloc (sizeof (UvSocksTunnel), n_params);
  if (!tunnels)
    {
      free (uvsocks);
      return NULL;
    }

  if (!uv_loop)
  {
    uvsocks->self_loop = 1;
    uvsocks->loop = malloc (sizeof (*uvsocks->loop));
    uv_loop_init (uvsocks->loop);
  }
  else
    uvsocks->loop = uv_loop;

  uvsocks->queue = aqueue_new (128);
  uv_async_init (uvsocks->loop, &uvsocks->async, uvsocks_receive_async);
  uvsocks->async.data = uvsocks;

  for (i = 0; i < n_params; i++)
    {
      tunnels[i].uvsocks = uvsocks;
      memcpy (&tunnels[i].param, &params[i], sizeof (UvSocksParam));
    }

  strlcpy (uvsocks->host, host, sizeof (uvsocks->host));
  uvsocks->port = port;
  strlcpy (uvsocks->user, user, sizeof (uvsocks->user));
  strlcpy (uvsocks->password, password, sizeof (uvsocks->password));

  uvsocks->n_tunnels = n_params;
  uvsocks->tunnels = tunnels;
  uvsocks->callback_func = callback_func;
  uvsocks->callback_data = callback_data;

  if (uvsocks->self_loop)
    uv_thread_create (&uvsocks->thread, uvsocks_thread_main, uvsocks);

  return uvsocks;

fail_parameter:
  if (callback_func)
    callback_func (NULL,
                   UVSOCKS_ERROR_PARAMETERS,
                   NULL,
                   callback_data);

  return NULL;
}

static void
uvsocks_session_set_stage (UvSocksSession *session,
                           UvSocksStage    stage)
{
  session->stage = stage;
}

static void
uvsocks_alloc_buffer (uv_handle_t *handle,
                      size_t       suggested_size,
                      uv_buf_t    *buf)
{
  UvSocksSessionLink *link = handle->data;
  size_t size;

  size = UVSOCKS_BUF_MAX - link->read_buf_len;
  if (size > suggested_size)
    size = suggested_size;

  if (size <= 0)
    return;

  buf->base = &link->read_buf[link->read_buf_len];
  buf->len = UV_BUF_LEN (size);
}

static void
uvsocks_free_handle_with_session (uv_handle_t *handle)
{
  UvSocksSessionLink *link = handle->data;
  UvSocksSession *session = link->session;

  free (handle);
  link->read_tcp = NULL;

  if (!session->socks.read_tcp && !session->local.read_tcp)
    {
      int s;

      for (s = 0; s < UVSOCKS_SESSION_MAX; s++)
        if (&session->tunnel->sessions[s] == session)
          {
            UvSocksTunnel  *tunnel = session->tunnel;
            tunnel->n_sessions--;
            session->tunnel = NULL;
            break;
          }
    }
}

static void
uvsocks_free_handle (uv_handle_t *handle)
{
  free (handle);
}

static void
uvsocks_remove_session (UvSocksTunnel  *tunnel,
                        UvSocksSession *session)
{
  if (!session)
    return;

  if (session->socks.read_tcp &&
      !uv_is_closing ((const uv_handle_t *)session->socks.read_tcp))
    uv_close ((uv_handle_t *) session->socks.read_tcp, uvsocks_free_handle_with_session);

  if (session->local.read_tcp &&
      !uv_is_closing ((const uv_handle_t *)session->local.read_tcp))
    uv_close ((uv_handle_t *) session->local.read_tcp, uvsocks_free_handle_with_session);
}

static void
uvsocks_free_tunnel (UvSocks *uvsocks)
{
  int t;
  int s;

  if (!uvsocks->tunnels)
    return;

  for (t = 0; t < uvsocks->n_tunnels; t++)
    {
      if (uvsocks->tunnels[t].listen_tcp)
        uv_close ((uv_handle_t *) uvsocks->tunnels[t].listen_tcp,
                  uvsocks_free_handle);

      for (s = 0; s < uvsocks->tunnels[t].n_sessions; s++)
        uvsocks_remove_session (&uvsocks->tunnels[t],
                                &uvsocks->tunnels[t].sessions[s]);
    }
}

static void
uvsocks_quit (UvSocks  *uvsocks,
              void     *data)
{
  if (uvsocks->self_loop)
    uv_stop (uvsocks->loop);
}

void
uvsocks_free (UvSocks *uvsocks)
{
  if (!uvsocks)
    return;

  uvsocks_free_tunnel (uvsocks);
  uvsocks_send_async (uvsocks, uvsocks_quit, NULL, NULL);

  if (uvsocks->self_loop)
    uv_thread_join (&uvsocks->thread);

  uv_close ((uv_handle_t *) &uvsocks->async, NULL);

  if (uvsocks->self_loop)
    {
      uv_loop_close (uvsocks->loop);
      free (uvsocks->loop);
    }

  free (uvsocks->tunnels);
  free (uvsocks);
}

static void
uvsocks_dns_resolved (uv_getaddrinfo_t  *resolver,
                      int                status,
                      struct addrinfo   *resolved)
{
  UvSocksSessionLink *link = resolver->data;

  if (status < 0)
    {
      UvSocksSession *session = link->session;
      UvSocksTunnel *tunnel;
      UvSocks *uvsocks;

      if (!session->tunnel)
        return;
      tunnel = session->tunnel;
      uvsocks = tunnel->uvsocks;

      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_DNS_RESOLVED,
                                &tunnel->param,
                                uvsocks->callback_data);
      uvsocks_remove_session (tunnel, session);

      uv_freeaddrinfo (resolved);
      return;
    }

  if (link->dns_resolve.func)
    link->dns_resolve.func (link, resolved);

  uv_freeaddrinfo (resolved);
}

static void
uvsocks_dns_resolve (UvSocks              *uvsocks,
                     const char           *host,
                     const int             port,
                     UvSocksDnsResolveFunc func,
                     void                 *data)
{
  UvSocksSessionLink *link = data;
  struct addrinfo hints;
  int status;
  char s[128];

  sprintf (s, "%i", port);

  hints.ai_family = PF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = 0;


  link->dns_resolve.data = data;
  link->dns_resolve.func = func;
  link->dns_resolve.getaddrinfo.data = link;

  status = uv_getaddrinfo (uvsocks->loop,
                           &link->dns_resolve.getaddrinfo,
                           uvsocks_dns_resolved,
                           host,
                           s,
                           &hints);
  if (status)
  {
    UvSocksSession *session = link->session;
    UvSocksTunnel *tunnel;
    UvSocks *uvsocks;

    if (!session->tunnel)
      return;
    tunnel = session->tunnel;
    uvsocks = tunnel->uvsocks;

    if (uvsocks->callback_func)
      uvsocks->callback_func (uvsocks,
                              UVSOCKS_ERROR_DNS_ADDRINFO,
                              &tunnel->param,
                              uvsocks->callback_data);
    uvsocks_remove_session (tunnel, session);
  }
}

static void
uvsocks_free_packet_after_set_stage (uv_write_t *req,
                                     int         status)
{
  UvSocksPacketReq *wr = (UvSocksPacketReq *) req;
  UvSocksSession *session = req->data;

  uvsocks_session_set_stage (session, wr->stage);

  free (wr);
}

static void
uvsocks_connected (uv_connect_t *connect,
                   int           status)
{
  UvSocksSessionLink *link = connect->data;
  UvSocksSession *session = link->session;
  UvSocksTunnel *tunnel;
  UvSocks *uvsocks;

  if (!session->tunnel)
    return;
  tunnel = session->tunnel;
  uvsocks = tunnel->uvsocks;

  if (status < 0)
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_CONNECTED,
                                &tunnel->param,
                                uvsocks->callback_data);
      uvsocks_remove_session (tunnel, session);
      free (connect);
      return;
    }

  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            UVSOCKS_OK_TCP_CONNECTED,
                            &tunnel->param,
                            uvsocks->callback_data);

  if (link->read_tcp == session->socks.read_tcp)
    {
      UvSocksPacketReq *wr;
      char buf[100];
      size_t buf_size;

      buf_size = 0;
      buf[buf_size++] = 0x05;
      buf[buf_size++] = 0x01;
      buf[buf_size++] = UVSOCKS_AUTH_PASSWD;

      wr = (UvSocksPacketReq *) malloc (sizeof *wr);
      wr->req.data = session;
      wr->buf = uv_buf_init (buf, (unsigned int) buf_size);
      wr->stage = UVSOCKS_STAGE_HANDSHAKE;

      uv_write ((uv_write_t *) wr,
                (uv_stream_t *) session->socks.read_tcp,
                &wr->buf,
                1,
                uvsocks_free_packet_after_set_stage);
    }
  else
    uvsocks_session_set_stage (session, UVSOCKS_STAGE_TUNNEL);

  if (uv_read_start ((uv_stream_t *) link->read_tcp,
                     uvsocks_alloc_buffer,
                     uvsocks_read))
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_READ_START,
                                &tunnel->param,
                                uvsocks->callback_data);
      uvsocks_remove_session (tunnel, session);
      free (connect);
      return;
    }
  free (connect);
}

static void
uvsocks_connect_real (UvSocksSessionLink *link,
                      struct addrinfo    *resolved)
{
  UvSocksSession *session = link->session;
  UvSocks *uvsocks;
  uv_connect_t *connect;

  if (!session->tunnel)
    return;
  uvsocks = session->tunnel->uvsocks;

  connect = malloc (sizeof (*connect));
  if (!connect)
    {
      UvSocksTunnel *tunnel = session->tunnel;
      UvSocks *uvsocks = tunnel->uvsocks;

      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR,
                                &tunnel->param,
                                uvsocks->callback_data);
      return;
    }

  link->read_tcp = malloc (sizeof (*link->read_tcp));
  if (!link->read_tcp)
    {
      UvSocksTunnel *tunnel = session->tunnel;
      UvSocks *uvsocks = tunnel->uvsocks;

      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR,
                                &tunnel->param,
                                uvsocks->callback_data);
      free (connect);
      return;
    }

  link->read_tcp->data = link;
  connect->data = link;

  uv_tcp_init (uvsocks->loop, link->read_tcp);
  uv_tcp_connect (connect,
                  link->read_tcp,
                  (const struct sockaddr *)resolved->ai_addr,
                  uvsocks_connected);
}

static void
uvsocks_read_start_after_free_packet (uv_write_t *req,
                                      int         status)
{
  UvSocksSessionLink *link = container_of (req, UvSocksSessionLink, write_req);

  link->read_buf_len = 0;
  uv_read_start ((uv_stream_t *) link->read_tcp,
                                 uvsocks_alloc_buffer,
                                 uvsocks_read);
}

static void
uvsocks_read (uv_stream_t    *stream,
              ssize_t         nread,
              const uv_buf_t *buf)
{
  UvSocksSessionLink *link = stream->data;
  UvSocksSession *session = link->session;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;
  char *data;
  size_t consume;

  if (nread < 0)
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_SOCKS_READ,
                                &tunnel->param,
                                uvsocks->callback_data);
      uvsocks_remove_session (tunnel, session);
      return;
    }
  if (nread == 0)
    return;

  link->read_buf_len += nread;
  data = link->read_buf;
  do
    {
      consume = 0;
      switch (session->stage)
        {
        case UVSOCKS_STAGE_NONE:
          break;
        case UVSOCKS_STAGE_HANDSHAKE:
          {
            if (link->read_buf_len < 2)
              break;

            if (session->socks.read_buf[0] != 0x05 ||
                session->socks.read_buf[1] != UVSOCKS_AUTH_PASSWD)
              {
                UvSocksTunnel *tunnel = session->tunnel;
                UvSocks *uvsocks = tunnel->uvsocks;

                if (uvsocks->callback_func)
                  uvsocks->callback_func (uvsocks,
                                          UVSOCKS_ERROR_SOCKS_HANDSHAKE,
                                          &tunnel->param,
                                          uvsocks->callback_data);
                uvsocks_remove_session (tunnel, session);
                return;
              }
            consume = 2;

            {
              UvSocksPacketReq *wr;
              char buf[100];
              size_t buf_size;
              size_t length;

              buf_size = 0;
              buf[buf_size++] = 0x01;
              length = strlen (uvsocks->user);
              buf[buf_size++] = (char) length;
              memcpy (&buf[buf_size], uvsocks->user, length);
              buf_size += length;

              length = strlen (uvsocks->password);
              buf[buf_size++] = (char) length;
              memcpy (&buf[buf_size], uvsocks->password, length);
              buf_size += length;

              wr = (UvSocksPacketReq *) malloc (sizeof *wr);
              wr->req.data = session;
              wr->buf = uv_buf_init (buf, (unsigned int) buf_size);
              wr->stage = UVSOCKS_STAGE_AUTHENTICATE;

              uv_write ((uv_write_t *) wr,
                        (uv_stream_t *) session->socks.read_tcp,
                        &wr->buf,
                        1,
                        uvsocks_free_packet_after_set_stage);
            }
          }
          break;
        case UVSOCKS_STAGE_AUTHENTICATE:
          {
            if (link->read_buf_len < 2)
              break;

            if (session->socks.read_buf[0] != 0x01 ||
                session->socks.read_buf[1] != UVSOCKS_AUTH_ALLOW)
              {
                if (uvsocks->callback_func)
                  uvsocks->callback_func (uvsocks,
                                          UVSOCKS_ERROR_SOCKS_AUTHENTICATION,
                                          &tunnel->param,
                                          uvsocks->callback_data);
                uvsocks_remove_session (tunnel, session);
                return;
              }
            consume = 2;

            {
              UvSocksPacketReq *wr;
              char buf[100];
              size_t buf_size;
              unsigned short port;
              struct sockaddr_in addr;

                buf_size = 0;
                buf[buf_size++] = 0x05;
                buf[buf_size++] = tunnel->param.is_forward ? UVSOCKS_CMD_CONNECT :
                                                             UVSOCKS_CMD_BIND;
                buf[buf_size++] = 0x00;
                buf[buf_size++] = UVSOCKS_ADDR_TYPE_IPV4;
                if (tunnel->param.is_forward)
                  {
                    uv_ip4_addr (tunnel->param.destination_host,
                                  tunnel->param.destination_port,
                                &addr);
                    port = htons (tunnel->param.destination_port);
                  }
                else
                  {
                    uv_ip4_addr (tunnel->param.listen_host,
                                  tunnel->param.listen_port,
                                &addr);
                    port = htons (tunnel->param.listen_port);
                  }
                memcpy (&buf[buf_size], &addr.sin_addr.s_addr, 4);
                buf_size += 4;
                memcpy (&buf[buf_size], &port, 2);
                buf_size += 2;

                wr = (UvSocksPacketReq *) malloc (sizeof *wr);
                wr->req.data = session;
                wr->buf = uv_buf_init (buf, (unsigned int) buf_size);
                wr->stage = UVSOCKS_STAGE_ESTABLISH;

                uv_write ((uv_write_t *) wr,
                          (uv_stream_t *) session->socks.read_tcp,
                          &wr->buf,
                          1,
                          uvsocks_free_packet_after_set_stage);
            }
          }
          break;
        case UVSOCKS_STAGE_ESTABLISH:
        case UVSOCKS_STAGE_BIND:
          {
            if (link->read_buf_len < 10)
              break;

            if (session->socks.read_buf[0] != 0x05 ||
                session->socks.read_buf[1] != 0x00)
              {
                if (uvsocks->callback_func)
                  uvsocks->callback_func (uvsocks,
                                          UVSOCKS_ERROR_SOCKS_COMMAND,
                                          &tunnel->param,
                                          uvsocks->callback_data);
                uvsocks_remove_session (tunnel, session);
                return;
              }

            consume = 10;

            if (session->stage == UVSOCKS_STAGE_ESTABLISH &&
                tunnel->param.is_forward == 0)
              {
                int port;

                memcpy (&port, &session->socks.read_buf[8], 2);
                port = htons(port);

                strlcpy (tunnel->param.listen_host, uvsocks->host, sizeof (tunnel->param.listen_host));
                tunnel->param.listen_port = port;

                if (uvsocks->callback_func)
                  uvsocks->callback_func (uvsocks,
                                          UVSOCKS_OK_SOCKS_BIND,
                                          &tunnel->param,
                                          uvsocks->callback_data);

                uvsocks_session_set_stage (session, UVSOCKS_STAGE_BIND);
                break;
              }

            if (session->stage == UVSOCKS_STAGE_BIND &&
                tunnel->param.is_forward == 0)
              {
                uvsocks_dns_resolve (uvsocks,
                                      tunnel->param.destination_host,
                                      tunnel->param.destination_port,
                                      uvsocks_connect_real,
                                      &session->local);
                break;
              }

            if (uvsocks->callback_func)
              uvsocks->callback_func (uvsocks,
                                      UVSOCKS_OK_SOCKS_CONNECT,
                                      &tunnel->param,
                                      uvsocks->callback_data);

            uvsocks_session_set_stage (session, UVSOCKS_STAGE_TUNNEL);
            if (uv_read_start ((uv_stream_t *) session->local.read_tcp,
                                uvsocks_alloc_buffer,
                                uvsocks_read))
              {
                if (uvsocks->callback_func)
                  uvsocks->callback_func (uvsocks,
                                          UVSOCKS_ERROR_TCP_READ_START,
                                          &tunnel->param,
                                          uvsocks->callback_data);
                uvsocks_remove_session (tunnel, session);
                return;
              }
          }
          break;
        case UVSOCKS_STAGE_TUNNEL:
          {
            int ret;
            uv_buf_t buf;

            buf = uv_buf_init (link->read_buf, (uint32_t) link->read_buf_len);
            ret = uv_try_write ((uv_stream_t*)link->write_link->read_tcp, &buf, 1);
            if (ret < 0)
              {
                UvSocksTunnel *tunnel = session->tunnel;
                UvSocks *uvsocks = tunnel->uvsocks;

                if (ret == UV_ENOSYS || ret == UV_EAGAIN)
                  {
                    if (UVSOCKS_BUF_MAX <= link->read_buf_len)
                      {
                        uv_read_stop ((uv_stream_t *) link->read_tcp);
                        uv_write (&link->write_req,
                                  (uv_stream_t *) (uv_stream_t*)link->write_link->read_tcp,
                                  &buf,
                                  1,
                                  uvsocks_read_start_after_free_packet);
                      }
                    return;
                  }

                if (uvsocks->callback_func)
                  uvsocks->callback_func (uvsocks,
                                          UVSOCKS_ERROR_TCP_SOCKS_READ,
                                          &tunnel->param,
                                          uvsocks->callback_data);
                uvsocks_remove_session (tunnel, session);
                return;
              }
            consume = ret;
          }
          break;
        }

      data += consume;
      link->read_buf_len -= consume;
    } while (consume && link->read_buf_len > 0);

  if (consume && link->read_buf_len)
    memcpy (link->read_buf, data, link->read_buf_len);
}

static UvSocksSession *
uvsocks_create_session (UvSocksTunnel  *tunnel)
{
  UvSocksSession *session;
  int id;

  id = -1;
  {
    int s;

    for (s = 0; s < UVSOCKS_SESSION_MAX; s++)
      if (tunnel->sessions[s].tunnel == NULL)
        {
          id = s;
          break;
        }
  }

  if (id < 0 ||
      tunnel->n_sessions >= UVSOCKS_SESSION_MAX)
    return NULL;

  tunnel->n_sessions++;

  session = &tunnel->sessions[id];
  session->local.read_buf_len = 0;
  session->local.session = session;
  session->local.write_link = &session->socks;

  session->socks.read_buf_len = 0;
  session->socks.session = session;
  session->socks.write_link = &session->local;

  session->tunnel = tunnel;

  uvsocks_session_set_stage (session, UVSOCKS_STAGE_NONE);

  return session;
}

static void
uvsocks_local_new_connection (uv_stream_t *stream,
                              int          status)
{
  UvSocksTunnel *tunnel = stream->data;
  UvSocks *uvsocks = tunnel->uvsocks;
  UvSocksSession *session;

  if (status == -1)
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_NEW_CONNECT,
                                &tunnel->param,
                                uvsocks->callback_data);
      return;
    }

  session = uvsocks_create_session (tunnel);
  if (!session)
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_CREATE_SESSION,
                                &tunnel->param,
                                uvsocks->callback_data);
      return;
    }

  session->local.read_tcp = malloc (sizeof (*session->local.read_tcp));
  if (!session->local.read_tcp)
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR,
                                &tunnel->param,
                                uvsocks->callback_data);
      return;
    }

  session->local.read_tcp->data = &session->local;

  uv_tcp_init (uvsocks->loop, session->local.read_tcp);
  if (uv_accept (stream, (uv_stream_t *) session->local.read_tcp))
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_ACCEPT,
                                &tunnel->param,
                                uvsocks->callback_data);

      if (session->local.read_tcp)
        uv_close ((uv_handle_t *) session->local.read_tcp, uvsocks_free_handle_with_session);
      return;
    }

  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            UVSOCKS_OK_TCP_NEW_CONNECT,
                            &tunnel->param,
                            uvsocks->callback_data);

  uvsocks_dns_resolve (uvsocks,
                       uvsocks->host,
                       uvsocks->port,
                       uvsocks_connect_real,
                       &session->socks);
}

static void
uvsocks_start_local_server (UvSocks       *uvsocks,
                            UvSocksTunnel *tunnel)
{
  UvSocksStatus status;
  struct sockaddr_in addr;
  int r;

  tunnel->listen_tcp = malloc (sizeof (*tunnel->listen_tcp));
  if (!tunnel->listen_tcp)
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_LOCAL_SERVER,
                                &tunnel->param,
                                uvsocks->callback_data);
      return;
    }

  uv_ip4_addr (tunnel->param.listen_host, tunnel->param.listen_port, &addr);
  uv_tcp_init (uvsocks->loop, tunnel->listen_tcp);
  r = uv_tcp_bind (tunnel->listen_tcp, (const struct sockaddr *) &addr, 0);
  if (r < 0)
    {
      status = UVSOCKS_ERROR_TCP_BIND;
      goto fail;
    }

  tunnel->listen_tcp->data = tunnel;

  {
    struct sockaddr_in name;
    int namelen;

    namelen = sizeof (name);
    uv_tcp_getsockname (tunnel->listen_tcp, (struct sockaddr *) &name, &namelen);
    tunnel->param.listen_port = ntohs (name.sin_port);
  }

  r = uv_listen ((uv_stream_t *) tunnel->listen_tcp, 16, uvsocks_local_new_connection);
  if (r < 0)
    {
      status = UVSOCKS_ERROR_TCP_LISTEN;
      goto fail;
    }

  status = UVSOCKS_OK_TCP_LOCAL_SERVER;
  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            status,
                            &tunnel->param,
                            uvsocks->callback_data);

  return;

fail:

  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            status,
                            &tunnel->param,
                            uvsocks->callback_data);

  if (tunnel->listen_tcp)
    uv_close ((uv_handle_t *) tunnel->listen_tcp, uvsocks_free_handle);

  return;
}

void
uvsocks_run (UvSocks *uvsocks)
{
  int i;

  if (!uvsocks)
    return;

  for (i = 0; i < uvsocks->n_tunnels; i++)
    if (uvsocks->tunnels[i].param.is_forward)
      uvsocks_start_local_server (uvsocks, &uvsocks->tunnels[i]);
    else
      {
        UvSocksSession *session;

        session = uvsocks_create_session (&uvsocks->tunnels[i]);
        if (!session)
          continue;

        uvsocks_dns_resolve (uvsocks,
                             uvsocks->host,
                             uvsocks->port,
                             uvsocks_connect_real,
                             &session->socks);
      }
}

const char *
uvsocks_get_status_string (UvSocksStatus status)
{
  switch (status)
    {
      case UVSOCKS_OK:
        return "normal success";
      case UVSOCKS_OK_TCP_LOCAL_SERVER:
        return "tcp success: local server";
      case UVSOCKS_OK_TCP_NEW_CONNECT:
        return "tcp success: new connect";
      case UVSOCKS_OK_TCP_CONNECTED:
        return "tcp success: connected";
      case UVSOCKS_OK_SOCKS_CONNECT:
        return "socks success: connect";
      case UVSOCKS_OK_SOCKS_BIND:
        return "socks success: bind";
      case UVSOCKS_ERROR:
        return "normal error";
      case UVSOCKS_ERROR_TCP_LOCAL_SERVER:
        return "tcp error: local server";
      case UVSOCKS_ERROR_TCP_PORT:
        return "tcp error: port";
      case UVSOCKS_ERROR_TCP_BIND:
        return "tcp error: bind";
      case UVSOCKS_ERROR_TCP_LISTEN:
        return "tcp error: listen";
      case UVSOCKS_ERROR_TCP_NEW_CONNECT:
        return "tcp error: new connect";
      case UVSOCKS_ERROR_TCP_CREATE_SESSION:
        return "tcp error: create session";
      case UVSOCKS_ERROR_TCP_ACCEPT:
        return "tcp error: accept";
      case UVSOCKS_ERROR_DNS_RESOLVED:
        return "dns error: resolved";
      case UVSOCKS_ERROR_DNS_ADDRINFO:
        return "dns error: address info";
      case UVSOCKS_ERROR_TCP_CONNECTED:
        return "tcp error: connected";
      case UVSOCKS_ERROR_TCP_READ_START:
        return "tcp error: read start";
      case UVSOCKS_ERROR_TCP_SOCKS_READ:
        return "tcp error: socks read";
      case UVSOCKS_ERROR_TCP_LOCAL_READ:
        return "tcp error: local read";
      case UVSOCKS_ERROR_SOCKS_HANDSHAKE:
        return "socks error: handshake";
      case UVSOCKS_ERROR_SOCKS_AUTHENTICATION:;
        return "socks error: authentication";
      case UVSOCKS_ERROR_SOCKS_COMMAND:
        return "socks error: command";
      case UVSOCKS_ERROR_SOCKS_CMD_BIND:
        return "socks error: bind";
    }

  return "unknown error";
}