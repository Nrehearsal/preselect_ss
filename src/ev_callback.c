#include <stdio.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <ev.h>

#include "preselect_ss.h"
#include "utils.h"
#include "utils_ss.h"
#include "ev_callback.h"
#include "server_ctx.h"
#include "resolve_ctx.h"
#include "resolve.h"
#include "config.h"
#include "china_ip.h"

static remote_t *connect_to_remote(EV_P_ struct sockaddr_in *addr);
static resolve_t *connect_to_nameserver(EV_P_ struct sockaddr_in *addr);

extern crypto_t *crypto;
extern config_t config;

void
accept_cb(EV_P_ ev_io *w, int revents)
{
	printf("[log]in accpet_cb\n");

	int rc = 0;

	listen_ctx_t *listen_ctx = (listen_ctx_t *)w;
	int serverfd = accept(listen_ctx->fd, NULL, NULL);
	if (serverfd == -1) {
		perror("[error]accept");
		return;
	}

	int opt = 1;
	setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
	set_nonblock(serverfd);

	//create a new server ctx
	server_t *server = new_server(serverfd, listen_ctx);	
	if (server != NULL) {
		/* only monitor read events and timeout events now*/
		ev_io_start(EV_A_ &server->recv_ctx->io);
		ev_timer_start(EV_A_ &server->recv_ctx->watcher->watcher);
		printf("[log]new connection coming\n");
	}

	return;
}

void 
server_recv_cb(EV_P_ ev_io *w, int revents)
{
	printf("[log]in server_recv_cb\n");

	server_ctx_t *server_recv_ctx = (server_ctx_t*)w;
	server_t *server = server_recv_ctx->server;
	buffer_t *buf = server->buf;
	remote_t *remote = NULL;
	

	/* make the timeout setting take effect first */
	/* and copy server data to remote buf */
	if (server->stage == STAGE_STREAM) {
		remote = server->remote;
		buf = remote->buf;
		ev_timer_again(EV_A_ & server->recv_ctx->watcher->watcher);
	}

	ssize_t rc = recv(server->fd, buf->data, SOCKET_BUF_SIZE, 0);
	if (rc == 0) {
		/* client closed */
		goto ERROR_RETURN;
	} 

	if (rc == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* no data, waiting for recv */
			goto NORMAL_RETURN;
		} 	
		/* error happend */
		goto ERROR_RETURN;
	}

	printf("[log]received %d from client.\n", (int)rc);
	buf->len = rc;

	if (server->stage == STAGE_INIT) {
		server->buf_copy->len = server->buf->len;
		memcpy(server->buf_copy->data, server->buf->data, SOCKET_BUF_SIZE);
	}

	if (server->stage == STAGE_INIT || remote->type == REMOTE_TYPE_PROXY) {
		rc = crypto->decrypt(buf, server->d_ctx, SOCKET_BUF_SIZE);
		if (rc == CRYPTO_ERROR) {
			goto ERROR_RETURN;
		}	
		if (rc == CRYPTO_NEED_MORE) {
			if (server->stage != STAGE_STREAM && server->frag < MAX_FRAG) {
				goto ERROR_RETURN;
			}
			server->frag++;
			goto NORMAL_RETURN;
		}
	}

	if (server->stage == STAGE_STREAM) {
		printf("[log]STAGE_STREAM\n");
		rc = send(remote->fd, remote->buf->data, remote->buf->len, 0);
		if (rc == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				remote->buf->idx = 0;
				ev_io_stop(EV_A_ &server_recv_ctx->io);
				ev_io_start(EV_A_ &remote->send_ctx->io);
				goto NORMAL_RETURN;
			}
			goto ERROR_RETURN;
		} 

		if (rc < remote->buf->len) {
			remote->buf->len -= rc;	
			remote->buf->idx = rc;

			ev_io_stop(EV_A_ &server_recv_ctx->io);
			ev_io_start(EV_A_ &remote->send_ctx->io);
			goto NORMAL_RETURN;
		}
		/* send all out */
		goto NORMAL_RETURN;
	}

	if (server->stage == STAGE_INIT) {
		printf("[log]STAGE_INIT\n");
		/* reference: https://shadowsocks.org/en/spec/Protocol.html */
		/* [1-byte type][variable-length host][2-byte port] */
		int offset = 0;
		/* max hostname length */
		char host[255] = {0};
		uint16_t port = 0;
		uint8_t name_len = 0;

		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(struct sockaddr_in));

		char atype = server->buf->data[offset++];
		if ((atype & 0Xf) == 1) {
			printf("[log]addr type\n");
			/* ipv4 */
			/* [1-byte type][variable-length host][2-byte port] */
			size_t in_addr_len = sizeof(struct in_addr);
			size_t min_len = 1 + in_addr_len + 2;

			if (server->buf->len < min_len) {
				printf("[error]invalid packet, packet length too small\n");
				goto ERROR_RETURN;
			}

			addr.sin_family = AF_INET;
			addr.sin_addr = *(struct in_addr *)(server->buf->data + offset);

			offset += in_addr_len;

			addr.sin_port = *(uint16_t*)(server->buf->data + offset);

			offset += 2;
			//copy server ip into host
			inet_ntop(AF_INET, &(addr.sin_addr), host, INET_ADDRSTRLEN);
			goto DO_CONNECT_REMOTE;
		} 

		if ((atype & 0xf) == 3) {
			/* domain name */
			printf("[log]domain type\n");

			name_len = *(uint8_t*)(server->buf->data + offset);
			offset += 1;
			/* [1-byte type][1-byte name_len][variable-length host][2-byte port] */
			size_t base_len = 1 + 1 + 2;	
			if (name_len + base_len > server->buf->len) {
				printf("[error]invalid host len\n");
				goto ERROR_RETURN;
			}

			memcpy(host, server->buf->data + offset, name_len);
			offset += name_len;

			int isip = 0;
			int isdomain = 0;
			/* special domain like this: https://192.168.1.1 */
			/* 1.1.1.1, 192.168.142.128 */
			if (name_len >= 7 && name_len <= 15) {
				isip = regex_ip(host);
			}

			if (isip) {
				//as ip
				printf("[log]ipv4 in host field\n");

				addr.sin_family = AF_INET;
				inet_pton(AF_INET, host, &(addr.sin_addr));
				addr.sin_port = *(uint16_t *)(server->buf->data + offset);

				printf("[log]host: %s\n", host);
				printf("[log]origin port: %d\n", ntohs(*(uint16_t *)(server->buf->data + offset)));

				offset += 2;
				goto DO_CONNECT_REMOTE;
			}

			/* general domain */
			isdomain = regex_domain(host);
			if (isdomain) {
				printf("[log]domain in host field\n");

				addr.sin_family = AF_INET;
				addr.sin_port = *(uint16_t *)(server->buf->data + offset);

				printf("[log]domain: %s\n", host);
				printf("[log]origin port: %d\n", ntohs(*(uint16_t *)(server->buf->data + offset)));

				offset += 2;
				goto DO_DOMAIN_RESOLVE;
			}

			printf("[log]bad host in feild\n");
			goto ERROR_RETURN;
		} 

		/* invalid type field */
		UNKOWN_TYPE:
			printf("[error]invalid type field\n");
			goto ERROR_RETURN;

		DO_DOMAIN_RESOLVE:
			if (server->buf->len < offset) {
				goto ERROR_RETURN;
			}

			server->buf->len -= offset;
			memmove(server->buf->data, server->buf->data + offset, server->buf->len);

			/* for nameserver connection */
			struct sockaddr_in nameserver_addr;
			//TODO get dns configuration from configuration file
			nameserver_addr.sin_family = AF_INET;
			nameserver_addr.sin_port = htons(53);
			//nameserver_addr.sin_addr.s_addr = INET_ADDR(1,1,1,1);
			inet_aton(config.nameserver, &nameserver_addr.sin_addr);

			resolve_t *resolve = connect_to_nameserver(EV_A_ &nameserver_addr);
			if (resolve == NULL) {
				goto ERROR_RETURN;
			}

			memcpy(resolve->addr, &addr, sizeof(struct sockaddr_in));
			resolve->caller = server;
			memcpy(resolve->domain, host, name_len);

			resolve->query_len = resolve_fill_query(resolve->buf, &resolve->dns_id,resolve->domain);
			resolve->buf_len = resolve->query_len;

			server->resolve = resolve;

			ev_io_stop(EV_A_ &server->recv_ctx->io);
			ev_io_start(EV_A_ &resolve->send_ctx->io);
			goto NORMAL_RETURN;

		DO_CONNECT_REMOTE:
			if (server->buf->len < offset) {
				goto ERROR_RETURN;
			}

			server->buf->len -= offset;
			memmove(server->buf->data, server->buf->data + offset, server->buf->len);

			remote_t *remote = connect_to_remote(EV_A_ &addr);
			if (remote == NULL) {
				goto ERROR_RETURN;
			}

			server->remote = remote;
			remote->server = server;

			if (remote->type == REMOTE_TYPE_PROXY) {
				if (server->buf->len > 0) {
					brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE);
					memcpy(remote->buf->data, server->buf->data, server->buf->len);
				}
				remote->buf->len = server->buf->len;
				remote->buf->idx = 0;
				server->buf->len = 0;
				server->buf->idx = 0;
			} else {
				server->buf->len = server->buf_copy->len;
				memcpy(server->buf->data, server->buf_copy->data, SOCKET_BUF_SIZE);

				if (server->buf->len > 0) {
					brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE);
					memcpy(remote->buf->data, server->buf->data, server->buf->len);
				}

				remote->buf->len = server->buf->len;
				remote->buf->idx = 0;

				server->buf->len = 0;
				server->buf->idx = 0;
			}

			ev_io_stop(EV_A_ &server->recv_ctx->io);
			ev_io_start(EV_A_ &remote->send_ctx->io);
			goto NORMAL_RETURN;
	}
ERROR_RETURN:
	close_and_free_remote(EV_A_ remote);
	close_and_free_server(EV_A_ server);
NORMAL_RETURN:
	return;
}


void 
server_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
	printf("[log]in server_timeout_cb\n");
	server_timeout_ctx_t *srv_timeout_ctx = (server_timeout_ctx_t *)watcher;

	server_t *server = srv_timeout_ctx->server;
	remote_t *remote = server->remote;

	close_and_free_remote(EV_A_ remote);
	close_and_free_server(EV_A_ server);
}

void
remote_send_cb(EV_P_ ev_io *w, int revents)
{
	printf("[log]in remote_send_cb\n");

	remote_ctx_t *remote_ctx = (remote_ctx_t *)w;
	remote_t *remote = remote_ctx->remote;
	server_t *server = remote->server;
	int payload_init_stage = 0;

	if (server == NULL) {
		printf("[error]invalid remote\n");
		goto ERROR_RETURN;
	}

	/* first time call remote_send_cb */
	if(!remote->send_ctx->connected) {
		printf("[log]first time to call remote_send_cb\n");
		struct sockaddr_in peer_addr;
		memset(&peer_addr, 0, sizeof(struct sockaddr_in));
		socklen_t addrlen = sizeof(struct sockaddr_in);
		int rc = getpeername(remote->fd, (struct sockaddr*)&peer_addr, &addrlen);
		if (rc != 0) {
			printf("[error]get peername error\n");
			goto ERROR_RETURN;
		}
		remote->send_ctx->connected = 1;
		server->stage = STAGE_STREAM;

		if (remote->buf->len == 0) {
			/*
			if (remote->type == REMOTE_TYPE_RELAY) {
				goto ERROR_RETURN;
			}
			*/

			/* no data in buf, poll server_recv_cb again */
			ev_io_stop(EV_A_ &remote->send_ctx->io);

			ev_io_start(EV_A_ &server->recv_ctx->io);
			ev_io_start(EV_A_ &remote->recv_ctx->io);
			goto NORMAL_RETURN;
		}
		payload_init_stage = 1;
	}

	if (remote->buf->len == 0) {
		printf("[error] no data in buf\n");
		goto ERROR_RETURN;
	}

	ssize_t rc = send(remote->fd, remote->buf->data + remote->buf->idx, remote->buf->len, 0);
	if (rc == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)  {
			/* busy, waiting for next send */	
			goto NORMAL_RETURN;
		}
		goto ERROR_RETURN;
	}

	printf("[log]buf length: %d\n", (int)remote->buf->len);
	printf("[log]send %d to remote\n", (int)rc);

	if (rc < remote->buf->len) {
		remote->buf->len -= rc;
		remote->buf->idx += rc;
		goto NORMAL_RETURN;
	}

	remote->buf->len = 0;
	remote->buf->idx = 0;
	ev_io_stop(EV_A_ &remote->send_ctx->io);

	if (server == NULL) {
		goto ERROR_RETURN;

	}

	/* has data send with init stage, or relay to upstream */
	if (payload_init_stage) {
		ev_io_start(EV_A_ &remote->recv_ctx->io);
	}

	ev_io_start(EV_A_ &server->recv_ctx->io);
	goto NORMAL_RETURN;

ERROR_RETURN:
	close_and_free_remote(EV_A_ remote);
	close_and_free_server(EV_A_ server);
NORMAL_RETURN:
	return;
}

void 
remote_recv_cb(EV_P_ ev_io *w, int revents)
{
	printf("[log]in remote_recv_cb\n");

	remote_ctx_t *remote_ctx = (remote_ctx_t *)w;
	remote_t *remote = remote_ctx->remote;
	server_t *server = remote->server;

	if (server == NULL) {
		printf("[error]invalid remote\n");
		goto ERROR_RETURN;
	}

	/* reset time clock */
	ev_timer_again(EV_A_ &server->recv_ctx->watcher->watcher);

	ssize_t rc = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);
	if (rc == 0) {
		/* remote closed */
		printf("[error]remote closed\n");
		goto ERROR_RETURN;
	}

	if (rc == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* no data, waiting for recv */
			goto NORMAL_RETURN;
		}
		perror("[error]remote recv error");
		goto ERROR_RETURN;
	}

	printf("[log]recv %d from remote\n", (int)rc);

	server->buf->len = rc;
	if (remote->type == REMOTE_TYPE_PROXY) {
		rc = crypto->encrypt(server->buf, server->e_ctx, SOCKET_BUF_SIZE);
		if (rc) {
			goto ERROR_RETURN;
		}
	}
	
	rc = send(server->fd, server->buf->data, server->buf->len, 0);
	if (rc == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			server->buf->idx = 0;
			ev_io_stop(EV_A_ &remote->recv_ctx->io);
			ev_io_start(EV_A_ &server->send_ctx->io);
			goto NORMAL_RETURN;
		}
		goto ERROR_RETURN;
	}

	if (rc < server->buf->len) {
		server->buf->len -= rc;
		server->buf->idx = rc;
		ev_io_stop(EV_A_ &remote->recv_ctx->io);
		ev_io_start(EV_A_ &server->send_ctx->io);
		goto NORMAL_RETURN;
	}
	
	if (!remote->recv_ctx->connected) {
		int opt = 0;
		setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
		setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
		remote->recv_ctx->connected = 1;
	}

	goto NORMAL_RETURN;

ERROR_RETURN:
	close_and_free_remote(EV_A_ remote);
	close_and_free_server(EV_A_ server);
NORMAL_RETURN:
	return;
}

void 
server_send_cb(EV_P_ ev_io *w, int revents)
{
	printf("[log]in server_recv_cb\n");


	server_ctx_t *server_ctx = (server_ctx_t *)w;
	server_t *server = server_ctx->server;
	remote_t *remote = server->remote;

	if (remote == NULL) {
		goto ERROR_RETURN;	
	}

	if (server->buf->len == 0) {
		/* no data, bad poll */
		goto ERROR_RETURN;
	}

	ssize_t rc = send(server->fd, server->buf->data + server->buf->idx, server->buf->len, 0);
	
	if (rc == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			goto NORMAL_RETURN;
		}
		goto ERROR_RETURN;
	}

	if (rc < server->buf->len) {
		server->buf->len -= rc;
		server->buf->idx += rc;
		goto NORMAL_RETURN;
	}

	server->buf->len = 0;
	server->buf->idx = 0;

	if (remote == NULL) {
		goto ERROR_RETURN;
	}

	ev_io_stop(EV_A_ &server->send_ctx->io);
	ev_io_start(EV_A_ &remote->recv_ctx->io);
	goto NORMAL_RETURN;

ERROR_RETURN:
	close_and_free_remote(EV_A_ remote);
	close_and_free_server(EV_A_ server);
NORMAL_RETURN:
	return;
}

void
resolve_send_cb(EV_P_ ev_io *w, int revents)
{
	printf("[log]in resolve_send_cb\n");

	resolve_ctx_t *resolve_ctx = (resolve_ctx_t *)w;
	resolve_t *resolve = resolve_ctx->resolve;
	server_t *server = resolve->caller;

	ssize_t rc = send(resolve->fd, resolve->buf + resolve->buf_idx, resolve->buf_len, MSG_NOSIGNAL);
	if (rc == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return;
		}
		close_and_free_resolve(EV_A_ resolve);
		close_and_free_server(EV_A_ server);
		perror("[error]send");
		return;
	}

	server->stage = STAGE_RESOLVE;

	printf("[log]send %d to dns server\n", (int)rc);
	if (rc < resolve->buf_len) {
		resolve->buf_len -= rc;
		resolve->buf_idx += rc;
		return;
	}

	ev_io_stop(EV_A_ &resolve->send_ctx->io);
	ev_io_start(EV_A_ &resolve->recv_ctx->io);
	return;
}

void
resolve_recv_cb(EV_P_ ev_io *w, int revents)
{
	printf("[log]in resolve_recv_cb\n");

	resolve_ctx_t *resolve_ctx = (resolve_ctx_t *)w;
	resolve_t *resolve = resolve_ctx->resolve;
	server_t *server = resolve->caller;
	
	size_t rc = recvfrom(resolve->fd, resolve->buf, sizeof(resolve->buf), MSG_NOSIGNAL, NULL, NULL);
	if (rc == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* no data, continue to poll read events for resolve */
			goto CONTINUE_RETURN;
		}
		/* error occued, close and free resolve, 
		 * server waiting for timeout events.
		 */
		goto FINAL_RETURN;
	}

	ipv4_t host = resolve_parse_resp(resolve->buf, rc, resolve->query_len, resolve->dns_id);		
	if (host != 0) {
		server_t *server = (server_t *)resolve->caller;

		resolve->addr->sin_addr.s_addr = host;

		remote_t *remote = connect_to_remote(EV_A_ resolve->addr);
		if (remote == NULL) {
			goto FINAL_RETURN;
		}

		server->remote = remote;
		remote->server = server;

		if (remote->type == REMOTE_TYPE_PROXY) {
			if (server->buf->len > 0) {
				brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE);
				memcpy(remote->buf->data, server->buf->data, server->buf->len);
			}
			remote->buf->len = server->buf->len;
			remote->buf->idx = 0;
			server->buf->len = 0;
			server->buf->idx = 0;
		} else {
			server->buf->len = server->buf_copy->len;
			memcpy(server->buf->data, server->buf_copy->data, SOCKET_BUF_SIZE);

			if (server->buf->len > 0) {
				brealloc(remote->buf, server->buf->len, SOCKET_BUF_SIZE);
				memcpy(remote->buf->data, server->buf->data, server->buf->len);
			}

			remote->buf->len = server->buf->len;
			remote->buf->idx = 0;

			server->buf->len = 0;
			server->buf->idx = 0;
		}

		server->stage = STAGE_STREAM;
		ev_io_start(EV_A_ &remote->send_ctx->io);
		goto FINAL_RETURN;
	}	

	printf("[error]no result for domain\n");

FINAL_RETURN:
	close_and_free_resolve(EV_A_ resolve);
CONTINUE_RETURN:
	return;
}

static remote_t *
connect_to_remote(EV_P_ struct sockaddr_in *addr) 
{
	printf("[log]in connect_to_remote\n");

	int sockfd;
	int rc;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("[error]create tcp socket failed in connect_to_remote");
		return NULL;
	}

	int opt = 1;
	setsockopt(sockfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	set_nonblock(sockfd);

	remote_t *remote = new_remote(sockfd);

	rc = is_china_ip(inet_ntoa(addr->sin_addr));
	if (rc == 1) {
		remote->type = REMOTE_TYPE_PROXY;
	} else {
		addr->sin_port = htons(config.upstream_port);
		inet_aton(config.upstream, &addr->sin_addr);
		remote->type = REMOTE_TYPE_RELAY;
	}

	printf("[log]start connect to %s:%d with tcp.\n", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
	rc = connect(sockfd, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
	if (rc == -1 && errno != EINPROGRESS) {
		//TODO close and free memory
		perror("[error]connect failed");
		free_remote(remote);
		return NULL;
	} 	

	printf("[log]connect to remote success\n");
	return remote;
}

static resolve_t *
connect_to_nameserver(EV_P_ struct sockaddr_in *addr) 
{
	printf("[log]in connect_to_nameserver\n");

	int sockfd;
	int rc;

	printf("[log]start connect to %s:%d with udp.\n", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		perror("[error]create dns socket failed in connect_to_nameserver");
		return NULL;
	}

	resolve_t *resolve = new_resolve(sockfd);
	if (resolve == NULL) {
		return NULL;
	}

	rc = connect(sockfd, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
	if (rc == -1) {
		perror("[error]connect failed");
		free_resolve(resolve);
		return NULL;
	}

	printf("[log]connect to nameserver success\n");

	return resolve;
}
