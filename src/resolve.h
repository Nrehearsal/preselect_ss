#ifndef _RESOLVE_H_
#define _RESOLVE_H_

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#define PROTO_DNS_QTYPE_A       1
#define PROTO_DNS_QCLASS_IP     1

struct dnshdr {
    uint16_t id, opts, qdcount, ancount, nscount, arcount;
};

struct dns_question {
    uint16_t qtype, qclass;
};

struct dns_resource {
    uint16_t type, _class;
    uint32_t ttl;
    uint16_t data_len;
} __attribute__((packed));


int resolve_fill_query(char *packet, uint16_t *dnsid,  char *domain);
ipv4_t resolve_parse_resp( char *response,  int response_len,  int query_len,  uint16_t dns_id);
#endif
