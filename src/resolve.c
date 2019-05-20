#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "resolve.h"
#include "mt_random.h"

static void 
resolve_domain_to_hostname(char *dst_hostname,  char *src_domain)
{
	int len = strlen(src_domain) + 1;
	char *lbl = dst_hostname, *dst_pos = dst_hostname + 1;
	uint8_t curr_len = 0;

	while (len-- > 0)
	{
		char c = *src_domain++;

		if (c == '.' || c == 0)
		{
			*lbl = curr_len;
			lbl = dst_pos++;
			curr_len = 0;
		}
		else
		{
			curr_len++;
			*dst_pos++ = c;
		}
	}
	*dst_pos = 0;
}

static void 
resolve_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
	unsigned int jumped = 0, offset;
	*count = 1;
	while(*reader != 0)
	{
		if(*reader >= 192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152;
			reader = buffer + offset - 1;
			jumped = 1;
		}
		reader = reader+1;
		if(jumped == 0)
			*count = *count + 1;
	}

	if(jumped == 1)
		*count = *count + 1;
}

int
resolve_fill_query(char *packet, uint16_t *dnsid,  char *domain) 
{
	struct dnshdr *dnsh = (struct dnshdr *)packet;
	char *qname = (char *)(dnsh + 1);
	resolve_domain_to_hostname(qname, domain);
	struct dns_question *dnst = (struct dns_question *)(qname + strlen(qname) + 1);
	uint16_t dns_id = rand_genrand_int32() % 0xffff;

	*dnsid = dns_id;
	dnsh->id = dns_id;
	dnsh->opts = htons(1 << 8); // Recursion desired
	dnsh->qdcount = htons(1);
	dnst->qtype = htons(PROTO_DNS_QTYPE_A);
	dnst->qclass = htons(PROTO_DNS_QCLASS_IP);

	int query_len = sizeof (struct dnshdr) + strlen(qname) + 1 + sizeof (struct dns_question);
	printf("[log]dns query len:%d\n", query_len);
	return query_len;
}

ipv4_t
resolve_parse_resp(char *response,  int resp_len,  int query_len,  uint16_t dns_id)
{
	struct dnshdr *dnsh = NULL;
	char *qname = NULL;
	struct dns_question *dnst = NULL;
	struct dnsans *dnsa = NULL;

	char *name;
	uint16_t ancount;
	int stop;

	ipv4_t host;

	if (resp_len < query_len) {
		printf("[log]resp_len < query_len\n");
		return 0;
	}

	dnsh = (struct dnshdr *)response;
	qname = (char *)(dnsh + 1);
	dnst = (struct dns_question *)(qname + strlen(qname) + 1);
	name = (char *)(dnst + 1);

	if (dnsh->id != dns_id) {
		printf("[log]dns id not match\n");
		return 0;
	}
	if (dnsh->ancount == 0) {
		printf("[log]ancount = 0\n");
		return 0;
	}

	ancount = ntohs(dnsh->ancount);
	while (ancount-- > 0)
	{
		struct dns_resource *r_data = NULL;

		resolve_skip_name(name, response, &stop);
		name = name + stop;

		r_data = (struct dns_resource *)name;
		name = name + sizeof(struct dns_resource);

		if (r_data->type == htons(PROTO_DNS_QTYPE_A) && r_data->_class == htons(PROTO_DNS_QCLASS_IP))
		{
			if (ntohs(r_data->data_len) == 4)
			{
				uint8_t tmp_buf[4];
				int i;
				for(i = 0; i < 4; i++) {
					tmp_buf[i] = name[i];
				}
				memcpy(&host, tmp_buf, sizeof(tmp_buf));
				break;
			}
			name = name + ntohs(r_data->data_len);
		} else {
			resolve_skip_name(name, response, &stop);
			name = name + stop;
		}
	}

	return host;
}
