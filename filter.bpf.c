#define BPF_NO_GLOBAL_DATA
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/netfilter.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "shared.h"

int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;

#define PRINTK(FMT, ...) ({ \
		char __fmt[] = "" FMT ""; \
		bpf_trace_printk(__fmt, sizeof(__fmt), __VA_ARGS__); \
	})

char LICENSE[] SEC("license") = "GPL";

struct bpf_nf_ctx {
	const struct nf_hook_state *state;
	struct __sk_buff *skb;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t); // must be 32 bit for BPF_MAP_TYPE_ARRAY
	__type(value, struct blocklist_item);
	__uint(max_entries, MAX_BLOCKLIST_ENTRIES);
} blocklist SEC(".maps");

static bool should_drop;
static bool done;
static struct ethhdr eth_header;
static struct iphdr ip_header;
static struct udphdr udp_header;

static uint64_t blocklist_iter_cb(
	void *map,
	uint32_t *key,
	struct blocklist_item *val,
	void *_arg
) {
	if (done)
		return 0;

	//if (strcmp(val->host, state->) == 0)
	//	state->should_block = true;

	if (val->is_last)
		done = true;
	return 0;
}

SEC("netfilter")
int dnsfilter(struct bpf_nf_ctx *ctx) {
	struct __sk_buff *skb = ctx->skb;

	// if the packet is too short to be a UDP packet, it can't be a dns request; allow it
	if (skb->data_end - skb->data < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))
		return NF_ACCEPT;

	struct bpf_dynptr dptr;
	bpf_dynptr_from_skb(skb, 0, &dptr);
	bpf_dynptr_read(&eth_header, sizeof(eth_header), &dptr, 0, 0);
	bpf_dynptr_read(&ip_header, sizeof(ip_header), &dptr, sizeof(eth_header), 0);
	bpf_dynptr_read(&udp_header, sizeof(udp_header), &dptr, sizeof(eth_header) + sizeof(ip_header), 0);

	// don't try to block the packet if it isn't UDP
	if (ip_header.protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	bpf_for_each_map_elem(&blocklist, blocklist_iter_cb, NULL, 0);
	if (should_drop)
		return NF_DROP;
	return NF_ACCEPT;
}
