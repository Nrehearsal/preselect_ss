#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdint.h>

typedef struct {
	char *password;
	char *method;
	char *ipdb;
	char *upstream;
	char *nameserver;
	uint16_t upstream_port;
	uint16_t port;
	int timeout;	
} config_t;

#endif
