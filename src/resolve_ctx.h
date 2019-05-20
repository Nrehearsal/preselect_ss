#ifndef _RESOLVE_CTX_H_
#define _RESOLVE_CTX_H_
#include <arpa/inet.h>

typedef struct {
	ev_io io;
	struct resolve_s *resolve;
} resolve_ctx_t;

typedef struct resolve_s {
	int fd;
	char domain[255];
	char buf[1024];

	int buf_idx;
	int buf_len;

	/* used to check the dns server response is valid*/
	int query_len;
	uint16_t dns_id;

	struct sockaddr_in *addr;

	resolve_ctx_t *recv_ctx;
	resolve_ctx_t *send_ctx;

	void *caller;
} resolve_t;

resolve_t *new_resolve(int fd);

void free_resolve(resolve_t *resolve);
void close_and_free_resolve(EV_P_ resolve_t *resolve);

#endif
