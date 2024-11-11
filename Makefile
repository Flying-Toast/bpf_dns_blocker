main: main.o filter.o shared.h
	clang main.o -o main -lbpf

filter.o: filter.bpf.c shared.h
	clang -O2 -target bpf -c filter.bpf.c -o filter.o -g

.PHONY: clean
clean:
	rm -f *.o
	rm -f main
