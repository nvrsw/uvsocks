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

#ifdef CONFIG_NEED_OFFSETOF
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *) 0)->MEMBER)
#endif

#ifdef _WIN32
#define container_of(ptr, type, member) (type *)((char *)ptr - offsetof (type, member))
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

typedef struct _UvSocksSessionLink UvSocksSessionLink;
struct _UvSocksSessionLink
{
  UvSocksSession       *session;

  uv_tcp_t             *read_tcp;
  char                 *read_buf;
  size_t                read_buf_len;
  UvSocksSessionLink   *write_link;
  uv_write_t            write_req;
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
  UvSocksSession        *sessions[UVSOCKS_SESSION_MAX];
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

typedef void (*UvSocksDnsResolveFunc) (UvSocksSessionLink *link,
                                       struct addrinfo    *resolved);
typedef struct _UvSocksDnsResolve UvSocksDnsResolve;
struct _UvSocksDnsResolve
{
  UvSocksDnsResolveFunc func;
  void                 *data;
};

typedef struct _UvSocksPacketReq UvSocksPacketReq;
struct _UvSocksPacketReq
{
  UvSocksSessionLink *restart_link;
  uv_write_t          req;
  uv_buf_t            buf;
};

static void
uvsocks_socks_login_req (UvSocksSessionLink *link);

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
  if (session->socks.read_tcp)
    uv_close ((uv_handle_t *) session->socks.read_tcp, uvsocks_free_handle);

  if (session->local.read_tcp)
    uv_close ((uv_handle_t *) session->local.read_tcp, uvsocks_free_handle);

  if (session->socks.read_buf)
    free (session->socks.read_buf);

  if (session->local.read_buf)
    free (session->local.read_buf);
 
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
    {
      for (s = 0; s < uvsocks->tunnels[t].n_sessions; s++)
        uvsocks_remove_session(&uvsocks->tunnels[t], uvsocks->tunnels[t].sessions[s]);

      if (uvsocks->tunnels[t].listen_tcp)
        uv_close ((uv_handle_t *) uvsocks->tunnels[t].listen_tcp, uvsocks_free_handle);
    }

  free (uvsocks->tunnels);
}

static void
uvsocks_free_async (uv_handle_t *handle)
{
  UvSocks *uvsocks = handle->data;

    if (uvsocks->self_loop)
    {
      uv_stop (uvsocks->loop);
      uv_thread_join (&uvsocks->thread);
      uv_loop_close (uvsocks->loop);
      free (uvsocks->loop);
    }

  free (uvsocks);
}

static void
uvsocks_quit (UvSocks  *uvsocks,
              void     *data)
{
  uv_close ((uv_handle_t *) &uvsocks->async, uvsocks_free_async);
}

void
uvsocks_free (UvSocks *uvsocks)
{
  if (!uvsocks)
    return;

  uvsocks_free_tunnel (uvsocks);
  uvsocks_send_async (uvsocks, uvsocks_quit, NULL, NULL);
}

static int
uvsocks_start_read (UvSocksSessionLink *link)
{
  return uv_read_start ((uv_stream_t *) link->read_tcp,
                                        uvsocks_alloc_buffer,
                                        uvsocks_read);
}

static void
uvsocks_status (UvSocksSessionLink *link,
                UvSocksStatus       status,
                int                 remove_session)
{
  UvSocksSession *session = link->session;
  UvSocksTunnel *tunnel = session->tunnel;
  UvSocks *uvsocks = tunnel->uvsocks;

  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            status,
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
  UvSocksSessionLink *link = d->data;

  if (status < 0)
    {
      uvsocks_status (link, UVSOCKS_ERROR_DNS_RESOLVED, 1);
      goto done;
    }

  if (d->func)
    d->func (link, resolved);

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
  UvSocksSessionLink *link = data;
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
    uvsocks_status (link, UVSOCKS_ERROR_DNS_ADDRINFO, 1);
    free (resolver);
  }
}

static void
uvsocks_connected (uv_connect_t *connect,
                   int           status)
{
  UvSocksSessionLink *link = connect->data;
  UvSocksSession *session = link->session;

  if (status < 0)
    {
      uvsocks_status (link, UVSOCKS_ERROR_TCP_CONNECTED, 1);
      free (connect);
      return;
    }
  uvsocks_status (link, UVSOCKS_OK_TCP_CONNECTED, 0);

  if (link->read_tcp == session->socks.read_tcp)
    uvsocks_socks_login_req (link);
  else
    uvsocks_session_set_stage (session, UVSOCKS_STAGE_TUNNEL);

  if (uvsocks_start_read (link))
    {
      uvsocks_status (link, UVSOCKS_ERROR_TCP_READ_START, 1);
      return;
    }
  free (connect);
}

static void
uvsocks_connect_real (UvSocksSessionLink *link,
                      struct addrinfo    *resolved)
{
  UvSocksSession *session = link->session;
  UvSocks *uvsocks = session->tunnel->uvsocks;
  uv_connect_t *connect;

  connect = malloc (sizeof (*connect));
  if (!connect)
    return;

  link->read_tcp = malloc (sizeof (*link->read_tcp));
  if (!link->read_tcp)
    return;

  uv_tcp_init (uvsocks->loop, link->read_tcp);

  link->read_tcp->data = link;
  connect->data = link;

  uv_tcp_connect (connect,
                  link->read_tcp,
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
uvsocks_write_packet (UvSocksSessionLink *link,
                      char               *packet,
                      size_t              size)
{
  uv_buf_t buf;

  buf = uv_buf_init (packet, (uint32_t) size);
  return uv_try_write ((uv_stream_t*)link->read_tcp, &buf, 1);
}

static void
uvsocks_free_packet_req (uv_write_t *req,
                         int         status)
{
  UvSocksSessionLink *link = container_of(req, UvSocksSessionLink, write_req);

  if (link->write_link)
    {
      link->write_link->read_buf_len = 0;
      uv_read_start ((uv_stream_t *) link->read_tcp,
                                     uvsocks_alloc_buffer,
                                     uvsocks_read);
    }
}

static void
uvsocks_write_packet0 (UvSocksSessionLink *link,
                       char               *packet,
                       size_t              len)
{
  uv_buf_t bufs[1];

  if (link->write_link)
    uv_read_stop ((uv_stream_t *) link->read_tcp);

  bufs[0].base = packet;
  bufs[0].len = UV_BUF_LEN (len);

  uv_write (&link->write_req,
            (uv_stream_t *) link->write_link->read_tcp,
            bufs,
            1,
            uvsocks_free_packet_req);
}

static void
uvsocks_socks_establish_req (UvSocksSessionLink *link)
{
  UvSocksSession *session = link->session;
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

  uvsocks_session_set_stage (link->session, UVSOCKS_STAGE_ESTABLISH);

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
  memcpy (&packet[packet_size], &addr.sin_addr.s_addr, 4);
  packet_size += 4;
  memcpy (&packet[packet_size], &port, 2);
  packet_size += 2;
  uvsocks_write_packet (link, packet, packet_size);
}

static int
uvsocks_socks_establish_ack (UvSocksSessionLink *link,
                             char               *buf,
                             ssize_t             read)
{
  UvSocksSession *session = link->session;
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

  if (session->socks.read_buf[0] != 0x05 ||
      session->socks.read_buf[1] != 0x00)
    {
      uvsocks_status (link, UVSOCKS_ERROR_SOCKS_COMMAND, 1);
      return 1;
    }

  if (session->stage == UVSOCKS_STAGE_ESTABLISH &&
      tunnel->param.is_forward == 0)
    {
      int port;

      memcpy (&port, &session->socks.read_buf[8], 2);
      port = htons(port);

      strlcpy (tunnel->param.listen_host, uvsocks->host, sizeof (tunnel->param.listen_host));
      tunnel->param.listen_port = port;
      uvsocks_status (link, UVSOCKS_OK_SOCKS_BIND, 0);
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

  uvsocks_status (link, UVSOCKS_OK_SOCKS_CONNECT, 0);
  uvsocks_session_set_stage (session, UVSOCKS_STAGE_TUNNEL);
  if (uvsocks_start_read (&session->local))
    {
      uvsocks_status (link, UVSOCKS_ERROR_TCP_READ_START, 1);
      return 1;
    }

  return 0;
}

static void
uvsocks_socks_auth_req (UvSocksSessionLink *link)
{
  UvSocksSession *session = link->session;
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

  uvsocks_write_packet (link, packet, packet_size);
}

static int
uvsocks_socks_auth_ack (UvSocksSessionLink *link,
                        char               *buf,
                        ssize_t             read)
{
  UvSocksSession *session = link->session;

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
  if (session->socks.read_buf[0] != 0x01 ||
      session->socks.read_buf[1] != UVSOCKS_AUTH_ALLOW)
    {
      uvsocks_status (link, UVSOCKS_ERROR_SOCKS_AUTHENTICATION, 1);
      return 1;
    }
  uvsocks_socks_establish_req (link);
  return 0;
}

static void
uvsocks_socks_login_req (UvSocksSessionLink *link)
{
  UvSocksSession *session = link->session;
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

  uvsocks_write_packet (link, packet, 3);
}

static int
uvsocks_socks_login_ack (UvSocksSessionLink *link,
                         char               *buf,
                         ssize_t             read)
{
  UvSocksSession *session = link->session;

  //+----+--------+
  //|VER | METHOD |
  //+----+--------+
  //| 1  |   1    |
  //+----+--------+
  //field 1: SOCKS version, 1 byte (0x05 for this version)
  //field 2: chosen authentication method, 1 byte, or 0xFF if no acceptable methods were offered
  if (read < 2)
    return 1;
  if (session->socks.read_buf[0] != 0x05 ||
      session->socks.read_buf[1] != UVSOCKS_AUTH_PASSWD)
    {
      uvsocks_status (link, UVSOCKS_ERROR_SOCKS_HANDSHAKE, 1);
      return 1;
    }
  uvsocks_socks_auth_req (link);
  return 0;
}

static void
uvsocks_read (uv_stream_t    *stream,
              ssize_t         nread,
              const uv_buf_t *buf)
{
  UvSocksSessionLink *link = stream->data;
  UvSocksSession *session = link->session;

  if (nread < 0)
    {
      uvsocks_status (link, UVSOCKS_ERROR_TCP_SOCKS_READ, 1);
      return;
    }
  if (nread == 0)
    return;

  if (session->stage == UVSOCKS_STAGE_TUNNEL)
    {
      int ret;

      link->read_buf_len += nread;
      ret = uvsocks_write_packet (link->write_link,
                                  link->read_buf,
                                  link->read_buf_len);
      if (ret < 0)
        {
          if (ret == UV_ENOSYS || ret == UV_EAGAIN)
            {
              if (UVSOCKS_BUF_MAX <= link->read_buf_len)
                uvsocks_write_packet0 (link,
                                       link->read_buf,
                                       link->read_buf_len);

              return;
            }
          uvsocks_status (link, UVSOCKS_ERROR_TCP_SOCKS_READ, 1);
        }
      link->read_buf_len -= ret;
      return;
    }
  if (session->stage == UVSOCKS_STAGE_HANDSHAKE)
    {
      uvsocks_socks_login_ack (link, link->read_buf, nread);
      return;
    }
  if (session->stage == UVSOCKS_STAGE_AUTHENTICATE)
    {
      uvsocks_socks_auth_ack (link, link->read_buf, nread);
      return;
    }
  if (session->stage == UVSOCKS_STAGE_ESTABLISH ||
      session->stage == UVSOCKS_STAGE_BIND)
    {
      uvsocks_socks_establish_ack (link, link->read_buf, nread);
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

  session->local.read_buf = malloc (UVSOCKS_BUF_MAX);
  session->local.read_buf_len = 0;
  session->local.session = session;
  session->local.write_link = &session->socks;

  session->socks.read_buf = malloc (UVSOCKS_BUF_MAX);
  session->socks.read_buf_len = 0;
  session->socks.session = session;
  session->socks.write_link = &session->local;

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
  UvSocksStatus socks_status;

  session = NULL;
  
  socks_status = UVSOCKS_ERROR_TCP_NEW_CONNECT;
  if (status == -1)
    goto fail;

  session = uvsocks_create_session (tunnel);
  if (!session)
    {
      socks_status = UVSOCKS_ERROR_TCP_CREATE_SESSION;
      goto fail;
    }

  session->local.read_tcp = malloc (sizeof (*session->local.read_tcp));
  if (!session->local.read_tcp)
    goto fail;
  session->local.read_tcp->data = &session->local;

  uv_tcp_init (uvsocks->loop, session->local.read_tcp);
  if (uv_accept (stream, (uv_stream_t *) session->local.read_tcp))
    {
      socks_status = UVSOCKS_ERROR_TCP_ACCEPT;
      goto fail;
    }

  socks_status = UVSOCKS_OK_TCP_NEW_CONNECT;
  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            socks_status,
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
                            socks_status,
                           &tunnel->param,
                            uvsocks->callback_data);
  uvsocks_remove_session (tunnel, session);
}

static int
uvsocks_start_local_server (UvSocks       *uvsocks,
                            UvSocksTunnel *tunnel)
{
  UvSocksStatus status;
  struct sockaddr_in addr;
  int r;

  if (tunnel->param.listen_port < 0 || tunnel->param.listen_port > 65535)
    {
      status = UVSOCKS_ERROR_TCP_PORT;
      goto fail;
    }

  tunnel->listen_tcp = malloc (sizeof (*tunnel->listen_tcp));
  if (!tunnel->listen_tcp)
    goto fail;

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

  return status;

fail:
  if (uvsocks->callback_func)
    uvsocks->callback_func (uvsocks,
                            status,
                            &tunnel->param,
                            uvsocks->callback_data);
  if (tunnel->listen_tcp)
    free (tunnel->listen_tcp);
  return status;
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
        uvsocks_connect (uvsocks,
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
      case UVSOCKS_ERROR_TCP_INSUFFICIENT_BUFFER:
        return "tcp error: insufficient buffer";
    }

  return "unknown error";
}