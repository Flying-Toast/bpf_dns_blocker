#include "shared.h"
#include <bpf/libbpf.h>
#include <err.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <linux/netfilter.h>
#include <sys/syscall.h>
#include <unistd.h>

int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size) {
	return syscall(SYS_bpf, cmd, attr, size);
}

int main(void) {
	struct bpf_object *obj = bpf_object__open_file("filter.o", NULL);
	if (obj == NULL)
		err(1, "bpf_object__open_file");

	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "dnsfilter");
	if (prog == NULL)
		err(1, "bpf_object__find_program_by_name");

	if (bpf_program__set_type(prog, BPF_PROG_TYPE_NETFILTER))
		err(1, "bpf_program__set_type");

	if (bpf_object__load(obj))
		err(1, "bpf_object__load");

	int progfd = bpf_program__fd(prog);
	if (progfd < 0)
		err(1, "bpf_program__fd %d", progfd);

	struct bpf_map *map = bpf_object__find_map_by_name(obj, "blocklist");
	if (map == NULL)
		err(1, "bpf_object__find_map_by_name");

	bpf_map__update_elem(
		map,
		&(uint32_t){0},
		sizeof(uint32_t),
		&(struct blocklist_item){.host = "example.com", .is_last = true},
		sizeof(struct blocklist_item),
		0
	);

	union bpf_attr attr = {};
	attr.link_create.prog_fd = progfd;
	attr.link_create.attach_type = BPF_NETFILTER;
	attr.link_create.netfilter.pf = NFPROTO_IPV4;
	attr.link_create.netfilter.hooknum = NF_INET_LOCAL_OUT;
	attr.link_create.netfilter.priority = -128;

	if (sys_bpf(BPF_LINK_CREATE, &attr, sizeof(attr)) == -1)
		err(1, "BPF_LINK_CREATE");


	for (;;)
		pause();
}
