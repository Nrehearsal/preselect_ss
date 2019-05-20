#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <ev.h>

#include "ev_callback.h"
#include "resolve_ctx.h"
#include "utils_ss.h"

resolve_t *
new_resolve(int fd) {
	resolve_t *resolve = ss_malloc(sizeof(resolve_t));
	memset(resolve, 0, sizeof(resolve_t));

	resolve->fd = fd;

	resolve->buf_len = 0;
	resolve->buf_idx = 0;

	resolve->query_len = 0;


	resolve->recv_ctx = ss_malloc(sizeof(resolve_ctx_t)); 
	resolve->send_ctx = ss_malloc(sizeof(resolve_ctx_t));
	memset(resolve->recv_ctx, 0, sizeof(resolve_ctx_t));
	memset(resolve->send_ctx, 0, sizeof(resolve_ctx_t));
	resolve->recv_ctx->resolve = resolve;
	resolve->send_ctx->resolve = resolve;

	resolve->addr = ss_malloc(sizeof(struct sockaddr_in));
	memset(resolve->addr, 0, sizeof(struct sockaddr_in));

	resolve->caller = NULL;

	ev_io_init(&resolve->send_ctx->io, resolve_send_cb, resolve->fd, EV_WRITE);
	ev_io_init(&resolve->recv_ctx->io, resolve_recv_cb, resolve->fd, EV_READ);

	return resolve;
}

void free_resolve(resolve_t *resolve)
{
	if (resolve->caller != NULL) {
		resolve->caller = NULL;
	}

	if (resolve->addr != NULL) {
		ss_free(resolve->addr);
	}

	ss_free(resolve->recv_ctx);
	ss_free(resolve->send_ctx);

	ss_free(resolve);
}

void
close_and_free_resolve(EV_P_ resolve_t *resolve)
{
	if (resolve != NULL) {
		printf("[log]in close_and_free_resolve\n");
		ev_io_stop(EV_A_ &resolve->recv_ctx->io);
		ev_io_stop(EV_A_ &resolve->send_ctx->io);
		close(resolve->fd);
		printf("[log]close_and_free_resolve start to free\n");
		free_resolve(resolve);
		printf("[log]close_and_free_resolve ok\n");
	}
}
