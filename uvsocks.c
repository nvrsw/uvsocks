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

#define UVSOCKS_BUF_MAX (1024 * 1024)

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

#define UVSOCKS_SESSION_MAX           16

typedef struct _UvSocksTunnel UvSocksTunnel;
typedef struct _UvSocksSession UvSocksSession;
struct _UvSocksSession
{
  UvSocksTunnel         *tunnel;
  UvSocksStage           stage;
  uv_tcp_t              *socks;
  uv_tcp_t              *local;
  size_t                 local_read;
  char                  *local_buf;
  size_t                 socks_read;
  char                  *socks_buf;
};

struct _UvSocksTunnel
{
  UvSocks               *uvsocks;
  UvSocksParam           param;
  uv_tcp_t              *server;
  int                    n_sessions;
  UvSocksSession        *sessions[UVSOCKS_SESSION_MAX];
};

struct _UvSocks
{
  uv_loop_t             *loop;
  AQueue                *queue;
  uv_async_t             async;

  char                   host[64];
  int                    port;
  char                   user[64];
  char                   password[64];
  int                    n_tunnels;
  UvSocksTunnel         *tunnels;

  UvSocksNotifyFunc      callback_func;
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

typedef void (*UvSocksDnsResolveFunc) (UvSocksSession  *session,
                                       struct addrinfo *resolved);
typedef struct _UvSocksDnsResolve UvSocksDnsResolve;
struct _UvSocksDnsResolve
{
  UvSocksDnsResolveFunc func;
  void                 *data;
};

typedef struct _UvSocksPacketReq UvSocksPacketReq;
struct _UvSocksPacketReq
{
  uv_write_t req;
  uv_buf_t   buf;
};

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

UvSocks *
uvsocks_new (void              *uv_loop,
             const char        *host,
             int                port,
             const char        *user,
             const char        *password,
             int                n_params,
             UvSocksParam      *params,
             UvSocksNotifyFunc  callback_func,
             void              *callback_data)
{
  UvSocks *uvsocks;
  UvSocksTunnel *tunnels;
  int i;

  if (!uv_loop)
    uv_loop = uv_default_loop ();

  uvsocks = calloc (sizeof (UvSocks), 1);
  if (!uvsocks)
    return NULL;

  uvsocks->loop = uv_loop;
  uvsocks->queue = aqueue_new (128);
  uv_async_init (uvsocks->loop, &uvsocks->async, uvsocks_receive_async);
  uvsocks->async.data = uvsocks;

  tunnels = calloc (sizeof (UvSocksTunnel), n_params);
  if (!tunnels)
    {
      uvsocks_free (uvsocks);
      return NULL;
    }
  for (i = 0; i < n_params; i++)
    {
      tunnels[i].uvsocks = uvsocks;
      memcpy (&tunnels[i].param, &params[i], sizeof (UvSocksParam));
    }
  strcpy (uvsocks->host, host);
  uvsocks->port = port;
  strcpy (uvsocks->user, user);
  strcpy (uvsocks->password, password);
  uvsocks->n_tunnels = n_params;
  uvsocks->tunnels = tunnels;
  uvsocks->callback_func = callback_func;
  uvsocks->callback_data = callback_data;

  return uvsocks;
}

static void
uvsocks_quit (UvSocks  *uvsocks,
              void     *data)
{
  uv_stop (uvsocks->loop);
}

static void
uvsocks_session_set_stage (UvSocksSession *session,
                          UvSocksStage    stage)
{
  session->stage = stage;
}

static UvSocksSession *
uvsocks_create_session (UvSocksTunnel  *tunnel)
{
  UvSocksSession *session;

  if (tunnel->n_sessions >= UVSOCKS_SESSION_MAX)
    return NULL;

  session = calloc (sizeof (UvSocksSession), 1);
  if (!session)
    return NULL;

  session->local = malloc (sizeof (*session->local));
  if (!session->local)
    goto fail;

  session->socks = malloc (sizeof (*session->socks));
  if (!session->socks)
    goto fail;

  session->local_buf = malloc (UVSOCKS_BUF_MAX);
  session->local_read = 0;
  session->socks_buf = malloc (UVSOCKS_BUF_MAX);
  session->socks_read = 0;

  session->local->data = session;
  session->socks->data = session;
  session->tunnel = tunnel;

  uvsocks_session_set_stage (session, UVSOCKS_STAGE_NONE);

  tunnel->sessions[tunnel->n_sessions++] = session;
  return session;

fail:
  if (session->socks)
    free (session->socks);
  if (session->local)
    free (session->local);
  free (session);

  return NULL;
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

  if (session->socks)
    {
      uv_read_stop ((uv_stream_t *)session->socks);
      uv_close ((uv_handle_t *) session->socks, uvsocks_free_handle);
    }

  if (session->local)
    {
      uv_read_stop ((uv_stream_t *) session->local);
      uv_close ((uv_handle_t *) session->local, uvsocks_free_handle);
    }

  if (session->socks_buf)
    free (session->socks_buf);
  if (session->local_buf)
    free (session->local_buf);
 
  free (session);
  //tunnel->n_sessions--;
}

static void
uvsocks_free_tunnel (UvSocks *uvsocks)
{
  int t;
  int s;

  if (!uvsocks->tunnels)
    return;

  for (t = 0; t < uvsocks->n_tunnels; t++)
    for (s = 0; s < uvsocks->tunnels[t].n_sessions; s++)
      uvsocks_remove_session (&uvsocks->tunnels[t], uvsocks->tunnels[t].sessions[s]);

  free (uvsocks->tunnels);
}

void
uvsocks_free (UvSocks *uvsocks)
{
  if (!uvsocks)
    return;

  uvsocks_free_tunnel (uvsocks);

  uvsocks_send_async (uvsocks, uvsocks_quit, NULL, NULL);
  uv_close ((uv_handle_t *) &uvsocks->async, NULL);
  uv_loop_close (uvsocks->loop);

  free (uvsocks);
}

static void
uvsocks_free_packet_req (uv_write_t *req,
                         int         status)
{
  free (req);
}

static void
uvsocks_write_packet (uv_tcp_t *tcp,
                      char     *packet,
                      size_t    len)
{
  int r;
  uv_buf_t buf;
  int written = 0;

  do {
    buf = uv_buf_init (&packet[written], len - written);
    r = uv_try_write ((uv_stream_t*)tcp, &buf, 1);

    if (r < 0)
      continue;

    written += r;
    if (len == written)
      break;
  } while (1);
}

static void
uvsocks_write_packet0 (uv_tcp_t *tcp,
                       char     *packet,
                       size_t    len)
{
  UvSocksPacketReq *req;

  req = (UvSocksPacketReq *) malloc (sizeof (*req));
  req->buf = uv_buf_init (packet, (unsigned int) len);
  uv_write ((uv_write_t *) req,
            (uv_stream_t *) tcp,
            &req->buf,
             1,
             uvsocks_free_packet_req);
}

static void
uvsocks_socks_login (UvSocksSession *session)
{
  char packet[20];
  size_t packet_size;

  uvsocks_session_set_stage (session, UVSOCKS_STAGE_HANDSHAKE);

  //+----+----------+----------+
  //|VER | NMETHODS | METHODS  |
  //+----+----------+----------+
  //| 1  |    1     | 1 to 255 |
  //+----+----------+----------+
  // The initial greeting from the client is
  // field 1: SOCKS version number (must be 0x05 for this version)
  // field 2: number of authentication methods supported, 1 byte
  // field 3: authentication methods, variable length, 1 byte per method supported
  packet_size = 0;
  packet[packet_size++] = 0x05;
  packet[packet_size++] = 0x01;
  packet[packet_size++] = UVSOCKS_AUTH_PASSWD;

  uvsocks_write_packet (session->socks, packet, 3);
}

static void
uvsocks_socks_auth (UvSocksSession *session)
{
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;
  char packet[1024];
  size_t packet_size;
  size_t length;

  uvsocks_session_set_stage (session, UVSOCKS_STAGE_AUTHENTICATE);

  //+----+------+----------+------+----------+
  //|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
  //+----+------+----------+------+----------+
  //| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
  //+----+------+----------+------+----------+
  //field 1: version number, 1 byte (must be 0x01)
  //field 2: username length, 1 byte
  //field 3: username
  //field 4: password length, 1 byte
  //field 5: password
  packet_size = 0;
  packet[packet_size++] = 0x01;
  length = strlen (uvsocks->user);
  packet[packet_size++] = (char) length;
  memcpy (&packet[packet_size], uvsocks->user, length);
  packet_size += length;

  length = strlen (uvsocks->password);
  packet[packet_size++] = (char) length;
  memcpy (&packet[packet_size], uvsocks->password, length);
  packet_size += length;

  uvsocks_write_packet (session->socks, packet, packet_size);
}

static void
uvsocks_socks_establish (UvSocksSession *session)
{
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;
  char packet[1024];
  size_t packet_size;
  unsigned short port;
  struct sockaddr_in addr;

  uvsocks_session_set_stage (session, UVSOCKS_STAGE_ESTABLISH);

  //+----+-----+-------+------+----------+----------+
  //|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
  //+----+-----+-------+------+----------+----------+
  //| 1  |  1  | X'00' |  1   | Variable |    2     |
  //+----+-----+-------+------+----------+----------+
  //The client's connection request is
  //field 1: SOCKS version number, 1 byte (must be 0x05 for this version)
  //field 2: command code, 1 byte:
  //0x01 = establish a TCP/IP stream connection
  //0x02 = establish a TCP/IP port binding
  //0x03 = associate a UDP port
  //
  //field 3: reserved, must be 0x00
  //field 4: address type, 1 byte:
  //0x01 = IPv4 address
  //0x03 = Domain name
  //0x04 = IPv6 address
  //
  //field 5: destination address of 4 bytes for IPv4 address
  //1 byte of name length followed by the name for domain name
  //16 bytes for IPv6 address
  //
  //field 6: port number in a network byte order, 2 bytes
  packet_size = 0;
  packet[packet_size++] = 0x05;
  packet[packet_size++] = tunnel->param.is_forward ? UVSOCKS_CMD_CONNECT :
                                                     UVSOCKS_CMD_BIND;
  packet[packet_size++] = 0x00;
  packet[packet_size++] = UVSOCKS_ADDR_TYPE_IPV4;
  if (tunnel->param.is_forward)
    {
      uv_ip4_addr (tunnel->param.socks_host,
                   tunnel->param.socks_port,
                  &addr);
      port = htons (tunnel->param.socks_port);
    }
  else
    {
      uv_ip4_addr (tunnel->param.local_host,
                   tunnel->param.local_port,
                  &addr);
      port = htons (tunnel->param.local_port);
    }
  memcpy (&packet[packet_size], &addr.sin_addr.S_un.S_addr, 4);
  packet_size += 4;
  memcpy (&packet[packet_size], &port, 2);
  packet_size += 2;
  uvsocks_write_packet (session->socks, packet, packet_size);
}

static void
uvsocks_dns_resolved (uv_getaddrinfo_t  *resolver,
                      int                status,
                      struct addrinfo   *resolved)
{
  UvSocksDnsResolve *d = resolver->data;
  UvSocksSession *session = d->data;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;

  if (status < 0)
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_DNS_RESOLVED,
                               &tunnel->param,
                                uvsocks->callback_data);

      uvsocks_remove_session (tunnel, session);
      goto done;
    }

  if (d->func)
    d->func (session, resolved);

done:
  uv_freeaddrinfo (resolved);
  free (resolver);
  free (d);
}

static void
uvsocks_dns_resolve (UvSocks              *uvsocks,
                     const char           *host,
                     const int             port,
                     UvSocksDnsResolveFunc func,
                     void                 *data)
{
  UvSocksSession *session = data;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocksDnsResolve *d;
  uv_getaddrinfo_t *resolver;
  struct addrinfo hints;
  int status;
  char s[128];

  sprintf (s, "%i", port);

  hints.ai_family = PF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = 0;

  resolver = malloc (sizeof (*resolver));
  if (!resolver)
    return;
  d = malloc (sizeof (*d));
  if (!d)
    {
      free (resolver);
      return;
    }

  d->data = data;
  d->func = func;
  resolver->data = d;

  status = uv_getaddrinfo (uvsocks->loop,
                           resolver,
                           uvsocks_dns_resolved,
                           host,
                           s,
                           &hints);
  if (status)
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_DNS_ADDRINFO,
                               &tunnel->param,
                                uvsocks->callback_data);

      uvsocks_remove_session (tunnel, session);
      free (resolver);
    }
}

static int
uvsocks_local_start_read (UvSocksSession *session);

static void
uvsocks_local_connected (uv_connect_t *connect,
                         int           status)
{
  UvSocksSession  *session = connect->data;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;

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
  uvsocks_session_set_stage (session, UVSOCKS_STAGE_TUNNEL);
  if (uvsocks_local_start_read (session))
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_READ_START,
                                &tunnel->param,
                                uvsocks->callback_data);

      uvsocks_remove_session (tunnel, session);
      return;
    }

  free (connect);
}

static void
uvsocks_connect_local_real (UvSocksSession  *session,
                            struct addrinfo *resolved)
{
  UvSocks *uvsocks = session->tunnel->uvsocks;
  uv_connect_t *connect;

  connect = malloc (sizeof (*connect));
  if (!connect)
    return;

  connect->data = session;
  uv_tcp_init (uvsocks->loop, session->local);
  uv_tcp_connect (connect,
                  session->local,
                  (const struct sockaddr *)resolved->ai_addr,
                  uvsocks_local_connected);
}

static int
uvsocks_connect_local (UvSocks        *uvsocks,
                       UvSocksSession *session,
                       const char     *host,
                       const int       port)
{
  uvsocks_dns_resolve (uvsocks,
                       host,
                       port,
                       uvsocks_connect_local_real,
                       session);
  return 0;
}

static void
uvsocks_socks_alloc_buffer (uv_handle_t *handle,
                            size_t       suggested_size,
                            uv_buf_t    *buf)
{
  UvSocksSession *session = handle->data;
  size_t size;

  size = UVSOCKS_BUF_MAX;
  if (size > suggested_size)
    size = suggested_size;

  buf->base = session->socks_buf;
  buf->len = UV_BUF_LEN (size);
}

static void
uvsocks_local_alloc_buffer (uv_handle_t *handle,
                            size_t       suggested_size,
                            uv_buf_t    *buf)
{
  UvSocksSession *session = handle->data;
  size_t size;

  size = UVSOCKS_BUF_MAX;
  if (size > suggested_size)
    size = suggested_size;

  buf->base = session->local_buf;
  buf->len = UV_BUF_LEN (size);
}

static void
uvsocks_local_read (uv_stream_t    *stream,
                    ssize_t         nread,
                    const uv_buf_t *buf)
{
  UvSocksSession *session = stream->data;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;

  if (nread < 0)
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_LOCAL_READ,
                               &tunnel->param,
                                uvsocks->callback_data);

      uvsocks_remove_session (tunnel, session);
      return;
    }
  if (nread == 0)
    return;

  uvsocks_write_packet (session->socks, session->local_buf, nread);
}

static int
uvsocks_local_start_read (UvSocksSession *session)
{
  return uv_read_start ((uv_stream_t *) session->local,
                                        uvsocks_local_alloc_buffer,
                                        uvsocks_local_read);
}

static int
uvsocks_connect_socks (UvSocks        *uvsocks,
                       UvSocksSession *session,
                       const char     *host,
                       const int       port);

static void
uvsocks_socks_read (uv_stream_t    *stream,
                    ssize_t         nread,
                    const uv_buf_t *buf)
{
  UvSocksSession *session = stream->data;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;

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

  switch (session->stage)
    {
      case UVSOCKS_STAGE_NONE:
      break;
      case UVSOCKS_STAGE_HANDSHAKE:
        {
          //+----+--------+
          //|VER | METHOD |
          //+----+--------+
          //| 1  |   1    |
          //+----+--------+
          //field 1: SOCKS version, 1 byte (0x05 for this version)
          //field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
          if (nread < 2)
            break;
          if (session->socks_buf[0] != 0x05 ||
              session->socks_buf[1] != UVSOCKS_AUTH_PASSWD)
            {
              if (uvsocks->callback_func)
                uvsocks->callback_func (uvsocks,
                                        UVSOCKS_ERROR_SOCKS_HANDSHAKE,
                                       &tunnel->param,
                                        uvsocks->callback_data);

              uvsocks_remove_session (tunnel, session);
              break;
            }
          uvsocks_socks_auth (session);
        }
      break;
      case UVSOCKS_STAGE_AUTHENTICATE:
        {
          //+----+--------+
          //|VER | STATUS |
          //+----+--------+
          //| 1  |   1    |
          //+----+--------+
          //field 1: version, 1 byte
          //field 2: status code, 1 byte 0x00 = success
          //any other value = failure, connection must be closed
          if (nread < 2)
            break;
          if (session->socks_buf[0] != 0x01 ||
              session->socks_buf[1] != UVSOCKS_AUTH_ALLOW)
            {
              if (uvsocks->callback_func)
                uvsocks->callback_func (uvsocks,
                                        UVSOCKS_ERROR_SOCKS_AUTHENTICATION,
                                       &tunnel->param,
                                        uvsocks->callback_data);

              uvsocks_remove_session (tunnel, session);
              break;
            }
          uvsocks_socks_establish (session);
        }
      break;
      case UVSOCKS_STAGE_ESTABLISH:
      case UVSOCKS_STAGE_BIND:
        {
          //field 1: SOCKS protocol version, 1 byte (0x05 for this version)
          //field 2: status, 1 byte:
          //0x00 = request granted
          //0x01 = general failure
          //0x02 = connection not allowed by ruleset
          //0x03 = network unreachable
          //0x04 = host unreachable
          //0x05 = connection refused by destination host
          //0x06 = TTL expired
          //0x07 = command not supported / protocol error
          //0x08 = address type not supported
          //
          //field 3: reserved, must be 0x00
          //field 4: address type, 1 byte: 0x01 = IPv4 address
          //0x03 = Domain name
          //0x04 = IPv6 address
          //
          //field 5: destination address of 4 bytes for IPv4 address
          //1 byte of name length followed by the name for domain name
          //16 bytes for IPv6 address
          //
          //field 6: network byte order port number, 2 bytes
          if (session->socks_buf[0] != 0x05 ||
              session->socks_buf[1] != 0x00)
            {
              if (uvsocks->callback_func)
                uvsocks->callback_func (uvsocks,
                                        UVSOCKS_ERROR_SOCKS_COMMAND,
                                       &tunnel->param,
                                        uvsocks->callback_data);

              uvsocks_remove_session (tunnel, session);
              break;
            }

          if (session->stage == UVSOCKS_STAGE_ESTABLISH &&
              tunnel->param.is_forward == 0)
            {
              int port;

              memcpy (&port, &session->socks_buf[8], 2);
              port = htons(port);

              tunnel->param.local_port = port;
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
              uvsocks_connect_local (uvsocks,
                                     session,
                                     tunnel->param.socks_host,
                                     tunnel->param.socks_port);
              break;
            }

          if (uvsocks->callback_func)
            uvsocks->callback_func (uvsocks,
                                    UVSOCKS_OK_SOCKS_CONNECT,
                                    &tunnel->param,
                                    uvsocks->callback_data);

          uvsocks_session_set_stage (session, UVSOCKS_STAGE_TUNNEL);
          if (uvsocks_local_start_read (session))
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
          uvsocks_write_packet (session->local, session->socks_buf, nread);
        }
      break;
    }
}

static int
uvsocks_socks_start_read (UvSocksSession *session)
{
  return uv_read_start ((uv_stream_t *) session->socks,
                                        uvsocks_socks_alloc_buffer,
                                        uvsocks_socks_read);
}

static void
uvsocks_socks_connected (uv_connect_t *connect,
                         int           status)
{
  UvSocksSession  *session = connect->data;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;

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

  uvsocks_socks_login (session);
  if (uvsocks_socks_start_read (session))
    {
      if (uvsocks->callback_func)
        uvsocks->callback_func (uvsocks,
                                UVSOCKS_ERROR_TCP_READ_START,
                                &tunnel->param,
                                uvsocks->callback_data);

      uvsocks_remove_session (tunnel, session);
      return;
    }

  free (connect);
}

static void
uvsocks_connect_socks_real (UvSocksSession  *session,
                            struct addrinfo *resolved)
{
  UvSocks *uvsocks = session->tunnel->uvsocks;
  uv_connect_t *connect;

  connect = malloc (sizeof (*connect));
  if (!connect)
    return;

  connect->data = session;
  uv_tcp_init (uvsocks->loop, session->socks);
  uv_tcp_connect (connect,
                  session->socks,
                  (const struct sockaddr *)resolved->ai_addr,
                  uvsocks_socks_connected);
}

static int
uvsocks_connect_socks (UvSocks        *uvsocks,
                       UvSocksSession *session,
                       const char     *host,
                       const int       port)
{
  uvsocks_dns_resolve (uvsocks,
                       host,
                       port,
                       uvsocks_connect_socks_real,
                       session);
  return 0;
}

static void
uvsocks_local_new_connection (uv_stream_t *stream,
                              int          status)
{
  UvSocksTunnel *tunnel = stream->data;
  UvSocks *uvsocks = tunnel->uvsocks;
  UvSocksSession *session;
  UvSocksNotify notify;

  notify = UVSOCKS_ERROR_TCP_NEW_CONNECT;

  if (!tunnel)
    goto fail;

  if (status == -1)
    goto fail;

  session = uvsocks_create_session (tunnel);
  if (!session)
    {
      notify = UVSOCKS_ERROR_TCP_CREATE_SESSION;
      goto fail;
    }

  uv_tcp_init (uvsocks->loop, session->local);
  if (uv_accept (stream, (uv_stream_t *) session->local))
    {
      notify = UVSOCKS_ERROR_TCP_ACCEPT;
      goto fail;
    }

  notify = UVSOCKS_OK_TCP_NEW_CONNECT;
  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            notify,
                           &tunnel->param,
                            uvsocks->callback_data);

  uvsocks_connect_socks (uvsocks,
                         session,
                         uvsocks->host,
                         uvsocks->port);
  return;
 
fail:
  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            notify,
                           &tunnel->param,
                            uvsocks->callback_data);
  uvsocks_remove_session (tunnel, session);
}

static int
uvsocks_start_local_server (UvSocks       *uvsocks,
                            UvSocksTunnel *tunnel)
{
  UvSocksNotify notify;
  struct sockaddr_in addr;
  struct sockaddr_in name;
  int namelen;
  int r;

  notify = UVSOCKS_ERROR_TCP_SERVER;

  if (!tunnel)
    goto fail;

  if (tunnel->param.local_port < 0 || tunnel->param.local_port > 65535)
    {
      notify = UVSOCKS_ERROR_TCP_PORT;
      goto fail;
    }

  uv_ip4_addr (tunnel->param.local_host, tunnel->param.local_port, &addr);

  tunnel->server = malloc (sizeof (*tunnel->server));
  if (!tunnel->server)
    goto fail;

  uv_tcp_init (uvsocks->loop, tunnel->server);

  r = uv_tcp_bind (tunnel->server, (const struct sockaddr *) &addr, 0);
  if (r < 0)
    {
      notify = UVSOCKS_ERROR_TCP_BIND;
      goto fail;
    }

  namelen = sizeof (name);
  uv_tcp_getsockname (tunnel->server, (struct sockaddr *) &name, &namelen);
  tunnel->param.local_port = ntohs (name.sin_port);

  r = uv_listen ((uv_stream_t *) tunnel->server, 16, uvsocks_local_new_connection);
  if (r < 0)
    {
      notify = UVSOCKS_ERROR_TCP_LISTEN;
      goto fail;
    }

  tunnel->server->data = tunnel;

  notify = UVSOCKS_OK_TCP_SERVER;
  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            notify,
                           &tunnel->param,
                            uvsocks->callback_data);

  return notify;

fail:
  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            notify,
                           &tunnel->param,
                            uvsocks->callback_data);
  if (tunnel->server)
    free (tunnel->server);
  return notify;
}

int
uvsocks_run (UvSocks *uvsocks)
{
  int i;

  if (!uvsocks)
    return UVSOCKS_ERROR;

  if (uvsocks->n_tunnels <= 0)
    return UVSOCKS_ERROR;

  for (i = 0; i < uvsocks->n_tunnels; i++)
    if (uvsocks->tunnels[i].param.is_forward)
      uvsocks_start_local_server (uvsocks, &uvsocks->tunnels[i]);
    else
      {
        UvSocksSession *session;

        session = uvsocks_create_session (&uvsocks->tunnels[i]);
        if (!session)
          continue;
        uvsocks_connect_socks (uvsocks,
                               session,
                               uvsocks->host,
                               uvsocks->port);
      }

  return UVSOCKS_OK;
}