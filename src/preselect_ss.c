#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <netdb.h>

#include "preselect_ss.h"
#include "utils.h"
#include "server_ctx.h"
#include "ev_callback.h"
#include "config.h"
#include "crypto.h"
#include "ipdb.h"


void 
usage() {
	printf("-c <conf> configuration file for preselect_ss\n");
	printf("-p <port> port for your ss server\n");
	printf("-k <password> password for your ss server\n");
	printf("-m <method> encrypt method for you ss server\n");
	printf("-t <timeout> proxy timeout\n");
	printf("-u <uhost> upstream host\n");
	printf("-l <uport> upstream port\n");
	printf("-d <ipdb> ipdb file\n");
	printf("-n <nameserver> dns nameserver\n");
}

	int 
main(int argc, char **argv)
{
	extern config_t config;
	extern crypto_t *crypto;
	extern ipdb_reader *ipdb_file_reader;

	crypto = NULL;

	config.port = 0;
	config.timeout = 0;
	config.password = NULL;
	config.method = NULL;
	config.ipdb = NULL;
	config.upstream = NULL;
	config.upstream_port = 0;

	int c;
	int rc;

	int listenfd;
	listen_ctx_t listen_ctx;
	struct sockaddr_in server_addr;
	struct ev_loop *loop = EV_DEFAULT;

	static struct option long_opts[] = {
		{ "conf",        required_argument, NULL, 'c'},
		{ "port",        required_argument, NULL, 'p'},
		{ "password",    required_argument, NULL, 'k'},
		{ "method",      required_argument, NULL, 'm'},
		{ "timeout",     required_argument, NULL, 't'},
		{ "uhost",       required_argument, NULL, 'u'},
		{ "uport",       required_argument, NULL, 'l'},
		{ "ipdb",        required_argument, NULL, 't'},
		{ "nameserver",  required_argument, NULL, 'n'},
		{ NULL,          0, 		    NULL,  0 }
	};

	opterr = 0;
	if (argc < 2) {
		usage();
		return -1;
	}

	while((c = getopt_long(argc, argv, "c:p:k:m:t:d:u:l:n:", long_opts, NULL)) != -1) {
		switch (c)
		{
			case 'c':
				//TODO parse configuration file.
				printf("configuration file path:%s\n", optarg);
				goto AFTER_GETOPT;
			case 'p':
				config.port = atoi(optarg);
				printf("parse port ok, port:%s\n", optarg);
				break;
			case 'k':
				config.password = optarg;
				printf("parse password ok, password:%s\n", optarg);
				break;
			case 'm':
				config.method = optarg;
				printf("parse crypto method ok, method:%s\n", optarg);
				break;
			case 't':
				config.timeout = atoi(optarg);
				printf("parse timeout ok, timeout:%s\n", optarg);
				break;
			case 'd':
				config.ipdb = optarg;
				printf("parse ipdb ok, ipdb:%s\n", optarg);
				break;
			case 'u':
				config.upstream = optarg;
				printf("parse upstream host ok, uhost:%s\n", optarg);
				break;
			case 'l':
				config.upstream_port = atoi(optarg);
				printf("parse upstream port ok, uport:%s\n", optarg);
				break;
			case 'n':
				config.nameserver = optarg;
				printf("parse nameserver ok, nameserver:%s\n", optarg);
				break;
			default:
				opterr = 1;
				break;
		}
	}

	if (opterr) {
		printf("cmdline args error\n");
		usage();		
		return -1;
	}

AFTER_GETOPT:
	/*
	 * set default arguments
	 */
	if (config.password == NULL) {
		printf("password can't be empty\n");
		return -1;
	}

	if (config.port == 0) {
		printf("port can't be empty\n");
		return -1;
	}

	if (config.ipdb == NULL) {
		printf("ipdb can't be empty\n");
		return -1;
	}

	if (config.ipdb == NULL) {
		config.nameserver = "1.1.1.1";
	}

	if (config.method == NULL) {
		config.method = "aes-128-cfb";
	}

	if (config.timeout == 0) {
		config.timeout = 60;
	}

	//TODO watch signal event
	
	printf("[log]init ipdb\n");
	rc = ipdb_reader_new(config.ipdb, &ipdb_file_reader);
	if (rc) {
		printf("crypto module init failed\n");		
		return -1;
	}
	printf("[log]ipdb init success\n");		

	printf("[log]init crypto method\n");
	crypto = crypto_init(config.password, NULL, config.method);
	if (crypto == NULL) {
		printf("crypto module init failed\n");		
		return -1;
	}
	printf("[log]crypto module init success\n");		

	printf("[log]start to listen and accept\n");
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		perror("create socket file failed");
		return -1;
	}

	bzero(&server_addr, sizeof(struct sockaddr_in));	
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(config.port);


	int opt = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	rc = bind(listenfd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr_in));
	if (rc == -1) {
		perror("bind socket failed");
		return -1;
	}
	rc = listen(listenfd, MAXCONN);
	if (rc == -1) {
		perror("listen socket failed");
		return -1;
	}

	set_nonblock(listenfd);

	listen_ctx.timeout = config.timeout;	
	listen_ctx.fd = listenfd;
	listen_ctx.iface = NULL;
	listen_ctx.loop = loop;

	ev_io_init(&listen_ctx.io, accept_cb, listenfd, EV_READ);
	ev_io_start(loop, &listen_ctx.io);

	ev_run(loop, 0);
}
