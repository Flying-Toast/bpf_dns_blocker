CFLAGS=-Wall -Wextra

filter.o: filter.bpf.c vmlinux.h
	clang $(CFLAGS) -O2 -target bpf -c filter.bpf.c -o filter.o -g

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: load
load: filter.o unload
	xdp-loader load -m skb -s xdp_dnsfilter wlp0s20f3 filter.o

.PHONY: unload
unload:
	-xdp-loader unload -a wlp0s20f3

.PHONY: clean
clean:
	rm -f *.o
	rm -f vmlinux.h
