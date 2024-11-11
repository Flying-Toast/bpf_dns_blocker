CFLAGS=-Wall -Wextra

main: main.o filter.o
	clang $(CFLAGS) main.o -o main -lbpf

main.o: shared.h

filter.o: filter.bpf.c shared.h vmlinux.h
	clang $(CFLAGS) -O2 -target bpf -c filter.bpf.c -o filter.o -g

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	rm -f *.o
	rm -f main
	rm -f vmlinux.h
