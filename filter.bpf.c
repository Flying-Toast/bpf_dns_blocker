#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#define PRINTK(FMT, ...) ({ \
		char __fmt[] = "" FMT ""; \
		bpf_trace_printk(__fmt, sizeof(__fmt), __VA_ARGS__); \
	})

#define ARRAY_LEN(ARR) (sizeof((ARR)) / sizeof((ARR)[0]))

#define LABEL(STR) { .len = sizeof("" STR "") - 1, .str = "" STR "" }

// ignore any names with more than this many labels (subdomains)
#define MAXLABELS 10

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
	__u16 transaction_id;

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

	__u16 num_questions;
	__u16 num_answers;
	__u16 num_authority_rrs;
	__u16 num_additional_rrs;
} __attribute__((packed));

struct label {
	__u8 len;
	__u8 str[255];
};

static struct ethhdr eth_header;
static struct iphdr ip_header;
static struct udphdr udp_header;
static struct dnshdr dns_header;

static const struct label blocklist[][MAXLABELS] = {
	{ LABEL("ads"), LABEL("google"), LABEL("com") },
};

char LICENSE[] SEC("license") = "GPL";

static bool memeq(void *va, void *vb, size_t n) {
	char *a = va;
	char *b = vb;
	while (n--) {
		if (a[n] != b[n])
			return false;
	}
	return true;
}

static bool matches(struct label *xs, struct label *ys) {
	for (__u8 i = 0; i < MAXLABELS; i++) {
		if ((xs[i].len == 0) != (ys[i].len == 0))
			return false;

		if (xs[i].len != ys[i].len)
			return false;

		if (!memeq(xs[i].str, ys[i].str, xs[i].len))
			return false;
	}

	return true;
}

SEC("xdp_dnsfilter")
int dnsfilter(struct xdp_md *ctx) {
	// if too small to possibly be a DNS packet, allow it.
	if (ctx->data_end - ctx->data <
		sizeof(eth_header)
		+ sizeof(ip_header)
		+ sizeof(udp_header)
		+ sizeof(dns_header))
	{
		return XDP_PASS;
	}

	struct bpf_dynptr dptr;
	bpf_dynptr_from_xdp(ctx, 0, &dptr);
	__u32 offset = 0;

	bpf_dynptr_read(&eth_header, sizeof(&eth_header), &dptr, offset, 0);
	offset += sizeof(eth_header);

	bpf_dynptr_read(&ip_header, sizeof(ip_header), &dptr, offset, 0);
	offset += sizeof(ip_header);
	if (ip_header.protocol != 0x11)
		return XDP_PASS; // not UDP

	bpf_dynptr_read(&udp_header, sizeof(udp_header), &dptr, offset, 0);
	offset += sizeof(udp_header);
	if (__bpf_ntohs(udp_header.source) != 53)
		return XDP_PASS; // not DNS

	bpf_dynptr_read(&dns_header, sizeof(dns_header), &dptr, offset, 0);
	offset += sizeof(dns_header);

	__u16 nquestions = __bpf_ntohs(dns_header.num_questions);
	if (nquestions > 255) {
		PRINTK("Too many questions (%hu > 255)\n", nquestions);
		return XDP_PASS;
	}

	for (__u8 qi = 0; qi < nquestions; qi++) {
		static struct label labels[MAXLABELS];
		for (int li = 0; li < MAXLABELS; li++) {
			__u8 lablen;
			bpf_dynptr_read(&lablen, sizeof(lablen), &dptr, offset, 0);
			offset += sizeof(lablen);
			labels[li].len = lablen;

			// null label marks end (see rfc883)
			if (lablen == 0)
				break;

			long err = bpf_dynptr_read(&labels[li].str, lablen, &dptr, offset, 0);
			offset += lablen;
			if (err) {
				PRINTK("err: %ld (E2BIG = %d, EINVAL = %d)\n", err, E2BIG, EINVAL);
				return XDP_PASS;
			}
		}

		for (__u8 blocklist_idx = 0; blocklist_idx < ARRAY_LEN(blocklist); blocklist_idx++) {
			if (matches(blocklist[blocklist_idx], labels)) {
				PRINTK("OVERWRITE THE ANSWER SECTION TO BLOCK%c\n", '!');
			}
		}
	}

	return XDP_PASS;
}
