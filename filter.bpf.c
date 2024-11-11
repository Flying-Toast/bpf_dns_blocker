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


static bool should_drop = false;
static bool done;
static struct __sk_buff *skb;

static uint64_t blocklist_iter_cb(
	void *map,
	uint32_t *key,
	struct blocklist_item *val,
	void *_arg
) {
	if (val->is_last)
		done = true;
	if (done)
		return 0;
	PRINTK("foofoo %u\n", *key);
	//if (strcmp(val->host, state->) == 0)
	//	state->should_block = true;
	return 0;
}

SEC("netfilter")
int dnsfilter(struct bpf_nf_ctx *ctx) {
	bpf_for_each_map_elem(&blocklist, blocklist_iter_cb, NULL, 0);
	if (should_drop)
		return NF_DROP;
	return NF_ACCEPT;
}
