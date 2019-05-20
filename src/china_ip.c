#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/time.h>

#include "ipdb.h"
#include "china_ip.h"

ipdb_reader *ipdb_file_reader;

int is_china_ip(const char *ip) {
	char body[512];
	char tmp[64];
	int err;
	int china_ip = 0;

	err = ipdb_reader_find(ipdb_file_reader, ip, "CN", body);
	if (err) {
		printf("[log]ipdb find err: %d\n", err);
		return 0;
	}
	/* printf("%s\n", body); */
	int f = 0, p1 = 0, p2 = -1;
	do {
		if (*(body + p1) == '\t' || !*(body + p1)) {
			strncpy(tmp, body + p2 + 1, (size_t) p1 - p2);
			tmp[p1 - p2] = 0;
			if (strcmp(tmp, "中国\t") == 0){
				china_ip = 1;
			}
			p2 = p1;
			++f;
		}
	} while (*(body + p1++));

	return china_ip;
}

/*
int main(void) {
	int err = ipdb_reader_new("ipipfree.ipdb", &ipdb_file_reader);
	if (err != 0) {
		printf("open ipdb file failed\n");
		return -1;
	}
	int rc = is_china_ip("110.165.32.1");
	if (rc) {
		printf("is china ip\n");
	} else {
		printf("is not china ip\n");
	}

	return 0;
}
*/
