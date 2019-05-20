#ifndef _SERVER_CTX_H_
#define _SERVER_CTX_H_

#include <ev.h>
#include "crypto.h"
#include "resolve_ctx.h"

#define MAX_FRAG 1
#define REMOTE_TYPE_PROXY 1
#define REMOTE_TYPE_RELAY 2

typedef struct {
	ev_io io;
	int fd;
	int timeout;
	char *iface;
	struct ev_loop *loop;
} listen_ctx_t;

typedef struct {
	ev_timer watcher;
	struct server_s *server;
} server_timeout_ctx_t;

typedef struct {
	ev_io io;
	server_timeout_ctx_t *watcher;
	int connected;
	struct server_s *server;
} server_ctx_t;

typedef struct server_s {
	int fd;
	int stage;
	int frag;

	buffer_t *buf;
	buffer_t *buf_copy;
	cipher_ctx_t *e_ctx;
	cipher_ctx_t *d_ctx;
	server_ctx_t *recv_ctx;
	server_ctx_t *send_ctx;
	listen_ctx_t *listen_ctx;

	struct remote_s *remote;
	resolve_t *resolve;
} server_t;

/*remote: the target address that the user actually want to access*/
typedef struct {
	ev_io io;
	int connected;
	struct remote_s *remote;
} remote_ctx_t;

typedef struct remote_s {
	int fd;
	buffer_t *buf;
	int type;

	remote_ctx_t *recv_ctx;
	remote_ctx_t *send_ctx;
	server_t *server;
} remote_t;

server_t *new_server(int fd, listen_ctx_t *listen_ctx);
remote_t *new_remote(int fd);

void free_remote(remote_t *remote);
void close_and_free_remote(EV_P_ remote_t* remote);
void free_server(server_t *server);
void close_and_free_server(EV_P_ server_t *server);

#endif
