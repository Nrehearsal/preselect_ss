#ifndef _UTILS_H_
#define _UTILS_H_

#define SOCKET_BUF_SIZE (16 * 1024 - 1)

int set_nonblock(int fd);
int regex_ip(const char *ip);
int regex_domain(const char *domain);

#endif
