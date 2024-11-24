#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#define PRINTK(FMT, ...) ({ \
		char __fmt[] = "" FMT ""; \
		bpf_trace_printk(__fmt, sizeof(__fmt), __VA_ARGS__); \
	})

char LICENSE[] SEC("license") = "GPL";

SEC("xdp_dnsfilter")
int dnsfilter(struct xdp_md *ctx) {
	struct bpf_dynptr dptr;
	bpf_dynptr_from_xdp(ctx, 0, &dptr);

	struct ethhdr eth_header;
	struct iphdr ip_header;
	struct udphdr udp_header;
	bpf_dynptr_read(&eth_header, sizeof(eth_header), &dptr, 0, 0);
	bpf_dynptr_read(&ip_header, sizeof(ip_header), &dptr, sizeof(eth_header), 0);
	bpf_dynptr_read(&udp_header, sizeof(udp_header), &dptr, sizeof(eth_header) + sizeof(ip_header), 0);

	int src_port = __bpf_ntohs(udp_header.source);

	if (src_port != 53)
		return XDP_PASS;

	return XDP_DROP;
}
