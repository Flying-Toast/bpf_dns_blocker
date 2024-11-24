#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#define PRINTK(FMT, ...) ({ \
		char __fmt[] = "" FMT ""; \
		bpf_trace_printk(__fmt, sizeof(__fmt), __VA_ARGS__); \
	})

// DNS flag macros
#define QR_QUERY 0
#define QR_REPLY 1
#define OPCODE_QUERY 0 // standard query
#define OPCODE_IQUERY 1 // inverse query
#define OPCODE_STATUS 2 // server status request
#define RESPCODE_NOERROR 0
#define RESPCODE_NXDOMAIN 3 // nonexistent domain

// see RFC 883 (https://www.rfc-editor.org/rfc/rfc883)
struct dnshdr {
	__u8 transaction_id;

	struct {
		int qr : 1; // compare with QR_* macros
		int opcode : 4; // compare with OPCODE_* macros
		int authoritative : 1;
		int truncated : 1;
		int recursion_desired : 1;
		int recursion_available : 1;
		int _reserved : 3;
		// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
		int respcode : 4;
	} __attribute__((packed)) flags;

	__u8 num_questions;
	__u8 num_answers;
	__u8 num_authority_rrs;
	__u8 num_additional_rrs;
} __attribute__((packed));

static struct ethhdr eth_header;
static struct iphdr ip_header;
static struct udphdr udp_header;
static struct dnshdr dns_header;

char LICENSE[] SEC("license") = "GPL";

static long parse(struct bpf_dynptr *dptr) {
	__u32 offset = 0;

	bpf_dynptr_read(&eth_header, sizeof(&eth_header), dptr, offset, 0);
	offset += sizeof(eth_header);

	bpf_dynptr_read(&ip_header, sizeof(ip_header), dptr, offset, 0);
	offset += sizeof(ip_header);

	bpf_dynptr_read(&udp_header, sizeof(udp_header), dptr, offset, 0);
	offset += sizeof(udp_header);

	bpf_dynptr_read(&dns_header, sizeof(dns_header), dptr, offset, 0);
	offset += sizeof(dns_header);

	return 0;
}

SEC("xdp_dnsfilter")
int dnsfilter(struct xdp_md *ctx) {
	// if too small to possibly be a DNS packet, allow it.
	if (ctx->data_end - ctx->data <
		sizeof(eth_header)
		+ sizeof(ip_header)
		+ sizeof(udp_header)
		+ sizeof(dns_header)
		+ 000000000000000000 /* TODO: ADD MORE */)
	{
		return XDP_PASS;
	}

	struct bpf_dynptr dptr;
	bpf_dynptr_from_xdp(ctx, 0, &dptr);

	parse(&dptr);

	if (__bpf_ntohs(udp_header.source) != 53)
		return XDP_PASS;

	return XDP_DROP;
}
