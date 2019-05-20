#include <stdlib.h>
#include <unistd.h>

#include "preselect_ss.h"
#include "server_ctx.h"
#include "ev_callback.h"
#include "utils.h"
#include "utils_ss.h"

extern crypto_t *crypto;

server_t *
new_server(int fd, listen_ctx_t *listen_ctx)
{
	server_t *server = malloc(sizeof(server_t));
	if (server == NULL) {
		return NULL;
	}

	memset(server, 0, sizeof(server_t));

	server->buf = ss_malloc(sizeof(buffer_t));
	server->buf_copy = ss_malloc(sizeof(buffer_t));
	server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
	server->send_ctx = ss_malloc(sizeof(server_ctx_t));

	balloc(server->buf, SOCKET_BUF_SIZE);
	balloc(server->buf_copy, SOCKET_BUF_SIZE);
	memset(server->recv_ctx, 0, sizeof(server_ctx_t));
	memset(server->send_ctx, 0, sizeof(server_ctx_t));

	server->fd = fd;
	server->send_ctx->server = server;
	server->send_ctx->connected = 0;

	server->recv_ctx->server = server;
	server->recv_ctx->connected = 0;

	server->recv_ctx->watcher = ss_malloc(sizeof(server_timeout_ctx_t));
	memset(server->recv_ctx->watcher, 0, sizeof(server_timeout_ctx_t));
	server->recv_ctx->watcher->server = server;

	server->e_ctx = ss_malloc(sizeof(cipher_ctx_t));
	server->d_ctx = ss_malloc(sizeof(cipher_ctx_t));
	crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
	crypto->ctx_init(crypto->cipher, server->d_ctx, 0);
	
	server->stage = STAGE_INIT;
	server->frag = 0;

	server->listen_ctx = listen_ctx;
	server->remote = NULL;
	server->resolve = NULL;

	/* init io event */
	ev_io_init(&server->recv_ctx->io, server_recv_cb, server->fd, EV_READ);
	ev_io_init(&server->send_ctx->io, server_send_cb, server->fd, EV_WRITE);
	/* init time clock event */
	ev_timer_init(&server->recv_ctx->watcher->watcher, server_timeout_cb, listen_ctx->timeout, listen_ctx->timeout);

	return server;
}

remote_t *
new_remote(int fd)
{
	remote_t *remote = malloc(sizeof(remote_t));
	if (remote == NULL) {
		return NULL;
	}
	memset(remote, 0, sizeof(remote_t));

	remote->fd = fd;
	remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
	remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
	remote->buf = ss_malloc(sizeof(buffer_t));

	memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
	remote->recv_ctx->remote = remote;
	memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
	remote->send_ctx->remote = remote;
	remote->recv_ctx->connected = 0;
	remote->send_ctx->connected = 0;

	balloc(remote->buf, SOCKET_BUF_SIZE);
	remote->server = NULL;
	
	ev_io_init(&remote->recv_ctx->io, remote_recv_cb, remote->fd, EV_READ);
	ev_io_init(&remote->send_ctx->io, remote_send_cb, remote->fd, EV_WRITE);

	return remote;
}

void 
free_remote(remote_t *remote)
{
	if (remote->server != NULL) {
		remote->server = NULL;
	}
	if (remote->buf != NULL) {
		bfree(remote->buf);
		ss_free(remote->buf);
	}
	ss_free(remote->recv_ctx);
	ss_free(remote->send_ctx);

	ss_free(remote);
}

void 
close_and_free_remote(EV_P_ remote_t *remote)
{
	if (remote != NULL) {
		ev_io_stop(EV_A_ &remote->recv_ctx->io);
		ev_io_stop(EV_A_ &remote->send_ctx->io);
		close(remote->fd);
		free_remote(remote);
		printf("[log]in close_and_free_remote, ok\n");
	}
}

void 
free_server(server_t *server)
{
	if (server->remote != NULL) {
		server->remote = NULL;
	}

	if (server->resolve != NULL) {
		server->resolve = NULL;
	}

	if (server->buf != NULL) {
		bfree(server->buf);
		ss_free(server->buf);
	}

	if (server->buf_copy != NULL) {
		bfree(server->buf_copy);
		ss_free(server->buf_copy);
	}

	if (server->e_ctx != NULL) {
		crypto->ctx_release(server->e_ctx);
		ss_free(server->e_ctx);
	}

	if (server->e_ctx != NULL) {
		crypto->ctx_release(server->d_ctx);
		ss_free(server->d_ctx);
	}

	server->recv_ctx->watcher->server = NULL;

	ss_free(server->recv_ctx->watcher);
	ss_free(server->recv_ctx);
	ss_free(server->send_ctx);
	ss_free(server);
}

void 
close_and_free_server(EV_P_ server_t *server)
{
	if (server != NULL) {
		ev_io_stop(EV_A_ &server->recv_ctx->io);
		ev_io_stop(EV_A_ &server->send_ctx->io);
		ev_timer_stop(EV_A_ &server->recv_ctx->watcher->watcher);
		close(server->fd);
		free_server(server);
		printf("[log]in close_and_free_server, ok\n");
	}
}
