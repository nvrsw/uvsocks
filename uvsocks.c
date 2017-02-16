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

typedef struct _UvSocksSessionTcp UvSocksSessionTcp;
struct _UvSocksSessionTcp
{
  UvSocksSession       *session;

  uv_tcp_t             *tcp;
  char                 *buf;
  size_t                read;
  uv_alloc_cb           alloc_cb;
  uv_read_cb            read_cb;
  UvSocksSessionTcp    *write;
};

struct _UvSocksSession
{
  UvSocksTunnel         *tunnel;
  UvSocksStage           stage;
  UvSocksSessionTcp      socks;
  UvSocksSessionTcp      local;
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

typedef void (*UvSocksDnsResolveFunc) (UvSocksSessionTcp *session_tcp,
                                       struct addrinfo   *resolved);
typedef struct _UvSocksDnsResolve UvSocksDnsResolve;
struct _UvSocksDnsResolve
{
  UvSocksDnsResolveFunc func;
  void                 *data;
};

typedef struct _UvSocksPacketReq UvSocksPacketReq;
struct _UvSocksPacketReq
{
  UvSocksSessionTcp *restart_tcp;
  uv_write_t         req;
  uv_buf_t           buf;
};

static void
uvsocks_socks_login_req (UvSocksSessionTcp *session_tcp);

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

static int
uvsocks_get_empty_session (UvSocksTunnel  *tunnel)
{
  int s;

  for (s = 0; s < UVSOCKS_SESSION_MAX; s++)
    if (tunnel->sessions[s] == NULL)
      return s;
  return -1;
}

static void
uvsocks_set_empty_session (UvSocksTunnel  *tunnel,
                           UvSocksSession *session)
{
  int s;

  for (s = 0; s < UVSOCKS_SESSION_MAX; s++)
    if (tunnel->sessions[s] == session)
      {
        tunnel->sessions[s] = NULL;
        break;
      }
}

static void
uvsocks_alloc_buffer (uv_handle_t *handle,
                      size_t       suggested_size,
                      uv_buf_t    *buf)
{
  UvSocksSessionTcp *session_tcp = handle->data;
  size_t size;

  size = UVSOCKS_BUF_MAX - session_tcp->read;
  if (size > suggested_size)
    size = suggested_size;

  if (size <= 0)
    return;

  buf->base = &session_tcp->buf[session_tcp->read];
  buf->len = UV_BUF_LEN (size);
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

  uvsocks_set_empty_session (tunnel, session);
  if (session->socks.tcp)
    {
      uv_read_stop ((uv_stream_t *)session->socks.tcp);
      uv_close ((uv_handle_t *) session->socks.tcp, uvsocks_free_handle);
    }

  if (session->local.tcp)
    {
      uv_read_stop ((uv_stream_t *) session->local.tcp);
      uv_close ((uv_handle_t *) session->local.tcp, uvsocks_free_handle);
    }

  if (session->socks.buf)
    free (session->socks.buf);
  if (session->local.buf)
    free (session->local.buf);
 
  free (session);
  tunnel->n_sessions--;
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

static int
uvsocks_start_read (UvSocksSessionTcp *socks_tcp)
{
  return uv_read_start ((uv_stream_t *) socks_tcp->tcp,
                                        socks_tcp->alloc_cb,
                                        socks_tcp->read_cb);
}

static void
uvsocks_notify (UvSocksSessionTcp *session_tcp,
                UvSocksNotify      notify,
                int                remove_session)
{
  UvSocksSession *session = session_tcp->session;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;

  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            notify,
                            &tunnel->param,
                            uvsocks->callback_data);
  if (remove_session)
    uvsocks_remove_session (tunnel, session);
}

static void
uvsocks_dns_resolved (uv_getaddrinfo_t  *resolver,
                      int                status,
                      struct addrinfo   *resolved)
{
  UvSocksDnsResolve *d = resolver->data;
  UvSocksSessionTcp *session_tcp = d->data;

  if (status < 0)
    {
      uvsocks_notify (session_tcp, UVSOCKS_ERROR_DNS_RESOLVED, 1);
      goto done;
    }

  if (d->func)
    d->func (session_tcp, resolved);

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
  UvSocksSessionTcp *session_tcp = data;
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
    uvsocks_notify (session_tcp, UVSOCKS_ERROR_DNS_ADDRINFO, 1);
    free (resolver);
  }
}

static void
uvsocks_connected (uv_connect_t *connect,
                   int           status)
{
  UvSocksSessionTcp *session_tcp = connect->data;
  UvSocksSession *session = session_tcp->session;

  if (status < 0)
    {
      uvsocks_notify (session_tcp, UVSOCKS_ERROR_TCP_CONNECTED, 1);
      free (connect);
      return;
    }
  uvsocks_notify (session_tcp, UVSOCKS_OK_TCP_CONNECTED, 0);

  if (session_tcp->tcp == session->socks.tcp)
    uvsocks_socks_login_req (session_tcp);
  else
    uvsocks_session_set_stage (session, UVSOCKS_STAGE_TUNNEL);

  if (uvsocks_start_read (session_tcp))
    {
      uvsocks_notify (session_tcp, UVSOCKS_ERROR_TCP_READ_START, 1);
      return;
    }
  free (connect);
}

static void
uvsocks_connect_real (UvSocksSessionTcp *session_tcp,
                      struct addrinfo   *resolved)
{
  UvSocksSession *session = session_tcp->session;
  UvSocks *uvsocks = session->tunnel->uvsocks;
  uv_connect_t *connect;

  connect = malloc (sizeof (*connect));
  if (!connect)
    return;

  session_tcp->tcp = malloc (sizeof (*session_tcp->tcp));
  if (!session_tcp->tcp)
    return;
  session_tcp->tcp->data = session_tcp;
  connect->data = session_tcp;

  uv_tcp_init (uvsocks->loop, session_tcp->tcp);
  uv_tcp_connect (connect,
                  session_tcp->tcp,
                  (const struct sockaddr *)resolved->ai_addr,
                  uvsocks_connected);
}

static void
uvsocks_connect (UvSocks              *uvsocks,
                 const char           *host,
                 const int             port,
                 UvSocksDnsResolveFunc callback_func,
                 void                 *callback_data)
{
  uvsocks_dns_resolve (uvsocks,
                       host,
                       port,
                       callback_func,
                       callback_data);
}

static int
uvsocks_write_packet (UvSocksSessionTcp *session_tcp,
                      char              *packet,
                      size_t             size)
{
  uv_buf_t buf;

  buf = uv_buf_init (packet, (uint32_t) size);
  return uv_try_write ((uv_stream_t*)session_tcp->tcp, &buf, 1);
}

static void
uvsocks_free_packet_req (uv_write_t *req,
                         int         status)
{
  UvSocksPacketReq *wr = (UvSocksPacketReq *) req;

  if (status < 0)
    return;

  if (wr->restart_tcp)
    {
      wr->restart_tcp->read = 0;
      uv_read_start ((uv_stream_t *) wr->restart_tcp->tcp,
                                     wr->restart_tcp->alloc_cb,
                                     wr->restart_tcp->read_cb);
    }
  free (wr);
}

static void
uvsocks_write_packet0 (UvSocksSessionTcp *session_tcp,
                       UvSocksSessionTcp *restart_tcp,
                       char              *packet,
                       size_t             size)
{
  UvSocksPacketReq *req;

  req = (UvSocksPacketReq *) malloc (sizeof (*req));
  req->buf = uv_buf_init (packet, (unsigned int) size);
  req->restart_tcp = restart_tcp;
  if (restart_tcp)
    uv_read_stop ((uv_stream_t *) restart_tcp->tcp);
  uv_write ((uv_write_t *) req,
            (uv_stream_t *) session_tcp->tcp,
            &req->buf,
             1,
             uvsocks_free_packet_req);
}

static void
uvsocks_socks_establish_req (UvSocksSessionTcp *session_tcp)
{
  UvSocksSession *session = session_tcp->session;
  UvSocksTunnel *tunnel = session->tunnel;
  char packet[1024];
  size_t packet_size;
  unsigned short port;
  struct sockaddr_in addr;

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

  uvsocks_session_set_stage (session_tcp->session, UVSOCKS_STAGE_ESTABLISH);

  packet_size = 0;
  packet[packet_size++] = 0x05;
  packet[packet_size++] = tunnel->param.is_forward ? UVSOCKS_CMD_CONNECT :
                                                     UVSOCKS_CMD_BIND;
  packet[packet_size++] = 0x00;
  packet[packet_size++] = UVSOCKS_ADDR_TYPE_IPV4;
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
  memcpy (&packet[packet_size], &addr.sin_addr.S_un.S_addr, 4);
  packet_size += 4;
  memcpy (&packet[packet_size], &port, 2);
  packet_size += 2;
  uvsocks_write_packet (session_tcp, packet, packet_size);
}

static int
uvsocks_socks_establish_ack (UvSocksSessionTcp *session_tcp,
                             char              *buf,
                             ssize_t            read)
{
  UvSocksSession *session = session_tcp->session;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;

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

  if (session->socks.buf[0] != 0x05 ||
      session->socks.buf[1] != 0x00)
    {
      uvsocks_notify (session_tcp, UVSOCKS_ERROR_SOCKS_COMMAND, 1);
      return 1;
    }

  if (session->stage == UVSOCKS_STAGE_ESTABLISH &&
      tunnel->param.is_forward == 0)
    {
      int port;

      memcpy (&port, &session->socks.buf[8], 2);
      port = htons(port);

      tunnel->param.listen_port = port;
      uvsocks_notify (session_tcp, UVSOCKS_OK_SOCKS_BIND, 0);
      uvsocks_session_set_stage (session, UVSOCKS_STAGE_BIND);
      return 0;
    }

  if (session->stage == UVSOCKS_STAGE_BIND &&
      tunnel->param.is_forward == 0)
    {
      uvsocks_connect (uvsocks,
                       tunnel->param.destination_host,
                       tunnel->param.destination_port,
                       uvsocks_connect_real,
                      &session->local);
      return 0;
    }

  uvsocks_notify (session_tcp, UVSOCKS_OK_SOCKS_CONNECT, 0);
  uvsocks_session_set_stage (session, UVSOCKS_STAGE_TUNNEL);
  if (uvsocks_start_read (&session->local))
    {
      uvsocks_notify (session_tcp, UVSOCKS_ERROR_TCP_READ_START, 1);
      return 1;
    }
  uv_read_stop ((uv_stream_t *)session->socks.tcp);
  if (uvsocks_start_read (&session->socks))
    {
      uvsocks_notify (session_tcp, UVSOCKS_ERROR_TCP_READ_START, 1);
      return 1;
    }
  return 0;
}

static void
uvsocks_socks_auth_req (UvSocksSessionTcp *session_tcp)
{
  UvSocksSession *session = session_tcp->session;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;
  char packet[1024];
  size_t packet_size;
  size_t length;

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

  uvsocks_session_set_stage (session, UVSOCKS_STAGE_AUTHENTICATE);

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

  uvsocks_write_packet (session_tcp, packet, packet_size);
}

static int
uvsocks_socks_auth_ack (UvSocksSessionTcp *session_tcp,
                        char              *buf,
                        ssize_t            read)
{
  UvSocksSession *session = session_tcp->session;

  //+----+--------+
  //|VER | STATUS |
  //+----+--------+
  //| 1  |   1    |
  //+----+--------+
  //field 1: version, 1 byte
  //field 2: status code, 1 byte 0x00 = success
  //any other value = failure, connection must be closed
  if (read < 2)
    return 1;
  if (session->socks.buf[0] != 0x01 ||
      session->socks.buf[1] != UVSOCKS_AUTH_ALLOW)
    {
      uvsocks_notify (session_tcp, UVSOCKS_ERROR_SOCKS_AUTHENTICATION, 1);
      return 1;
    }
  uvsocks_socks_establish_req (session_tcp);
  return 0;
}

static void
uvsocks_socks_login_req (UvSocksSessionTcp *session_tcp)
{
  UvSocksSession *session = session_tcp->session;
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

  uvsocks_write_packet (session_tcp, packet, 3);
}

static int
uvsocks_socks_login_ack (UvSocksSessionTcp *session_tcp,
                         char              *buf,
                         ssize_t            read)
{
  UvSocksSession *session = session_tcp->session;

  //+----+--------+
  //|VER | METHOD |
  //+----+--------+
  //| 1  |   1    |
  //+----+--------+
  //field 1: SOCKS version, 1 byte (0x05 for this version)
  //field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
  if (read < 2)
    return 1;
  if (session->socks.buf[0] != 0x05 ||
      session->socks.buf[1] != UVSOCKS_AUTH_PASSWD)
    {
      uvsocks_notify (session_tcp, UVSOCKS_ERROR_SOCKS_HANDSHAKE, 1);
      return 1;
    }
  uvsocks_socks_auth_req (session_tcp);
  return 0;
}

static void
uvsocks_read (uv_stream_t    *stream,
              ssize_t         nread,
              const uv_buf_t *buf)
{
  UvSocksSessionTcp *session_tcp = stream->data;
  UvSocksSession *session = session_tcp->session;

  if (nread < 0)
    {
      uvsocks_notify (session_tcp, UVSOCKS_ERROR_TCP_SOCKS_READ, 1);
      return;
    }
  if (nread == 0)
    return;

  if (session->stage == UVSOCKS_STAGE_TUNNEL)
    {
      int ret;

      session_tcp->read += nread;
      ret = uvsocks_write_packet (session_tcp->write,
                                  session_tcp->buf,
                                  session_tcp->read);
      if (ret < 0)
        {
          if (ret == UV_ENOSYS || ret == UV_EAGAIN)
            {
              #if 0
              uvsocks_write_packet0 (session_tcp->write,
                                     session_tcp,
                                     session_tcp->buf,
                                     session_tcp->read);
              #endif
              if (UVSOCKS_BUF_MAX - session_tcp->read <= 0)
                uvsocks_write_packet0 (session_tcp->write,
                                       session_tcp,
                                       session_tcp->buf,
                                       session_tcp->read);

              return;
            }
          uvsocks_notify (session_tcp, UVSOCKS_ERROR_TCP_SOCKS_READ, 1);
        }
      session_tcp->read -= ret;
      return;
    }
  if (session->stage == UVSOCKS_STAGE_HANDSHAKE)
    {
      uvsocks_socks_login_ack (session_tcp, session_tcp->buf, nread);
      return;
    }
  if (session->stage == UVSOCKS_STAGE_AUTHENTICATE)
    {
      uvsocks_socks_auth_ack (session_tcp, session_tcp->buf, nread);
      return;
    }
  if (session->stage == UVSOCKS_STAGE_ESTABLISH ||
      session->stage == UVSOCKS_STAGE_BIND)
    {
      uvsocks_socks_establish_ack (session_tcp, session_tcp->buf, nread);
      return;
    }
}

static UvSocksSession *
uvsocks_create_session (UvSocksTunnel  *tunnel)
{
  UvSocksSession *session;
  int empty;

  empty = uvsocks_get_empty_session (tunnel);
  if (empty < 0 ||
      tunnel->n_sessions >= UVSOCKS_SESSION_MAX)
    return NULL;

  tunnel->n_sessions++;
  session = calloc (sizeof (UvSocksSession), 1);
  if (!session)
    return NULL;

  session->local.buf = malloc (UVSOCKS_BUF_MAX);
  session->local.read = 0;
  session->local.session = session;
  session->local.alloc_cb = uvsocks_alloc_buffer;
  session->local.read_cb = uvsocks_read;
  session->local.write = &session->socks;

  session->socks.buf = malloc (UVSOCKS_BUF_MAX);
  session->socks.read = 0;
  session->socks.session = session;
  session->socks.alloc_cb = uvsocks_alloc_buffer;
  session->socks.read_cb = uvsocks_read;
  session->socks.write = &session->local;

  session->tunnel = tunnel;

  uvsocks_session_set_stage (session, UVSOCKS_STAGE_NONE);

  tunnel->sessions[empty] = session;
  return session;
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
  if (status == -1)
    goto fail;

  session = uvsocks_create_session (tunnel);
  if (!session)
    {
      notify = UVSOCKS_ERROR_TCP_CREATE_SESSION;
      goto fail;
    }

  session->local.tcp = malloc (sizeof (*session->local.tcp));
  if (!session->local.tcp)
    goto fail;
  session->local.tcp->data = &session->local;

  uv_tcp_init (uvsocks->loop, session->local.tcp);
  if (uv_accept (stream, (uv_stream_t *) session->local.tcp))
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

  uvsocks_connect (uvsocks,
                   uvsocks->host,
                   uvsocks->port,
                   uvsocks_connect_real,
                  &session->socks);
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
  if (tunnel->param.listen_port < 0 || tunnel->param.listen_port > 65535)
    {
      notify = UVSOCKS_ERROR_TCP_PORT;
      goto fail;
    }

  uv_ip4_addr (tunnel->param.listen_host, tunnel->param.listen_port, &addr);

  tunnel->server = malloc (sizeof (*tunnel->server));
  if (!tunnel->server)
    goto fail;
  tunnel->server->data = tunnel;

  uv_tcp_init (uvsocks->loop, tunnel->server);

  r = uv_tcp_bind (tunnel->server, (const struct sockaddr *) &addr, 0);
  if (r < 0)
    {
      notify = UVSOCKS_ERROR_TCP_BIND;
      goto fail;
    }

  namelen = sizeof (name);
  uv_tcp_getsockname (tunnel->server, (struct sockaddr *) &name, &namelen);
  tunnel->param.listen_port = ntohs (name.sin_port);

  r = uv_listen ((uv_stream_t *) tunnel->server, 16, uvsocks_local_new_connection);
  if (r < 0)
    {
      notify = UVSOCKS_ERROR_TCP_LISTEN;
      goto fail;
    }

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
        uvsocks_connect (uvsocks,
                         uvsocks->host,
                         uvsocks->port,
                         uvsocks_connect_real,
                        &session->socks);
      }

  return UVSOCKS_OK;
}