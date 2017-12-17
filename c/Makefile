
.PHONY: all
all: bin/arp bin/route bin/ndp bin/get_default_router bin/get_rt_table bin/bpf

bin/:
	mkdir bin

bin/arp: bin/
	cc arp.c -o bin/arp

bin/route: bin/
	cc route.c -o bin/route

bin/ndp: bin/
	cc ndp.c -o bin/ndp

bin/get_default_router: bin/
	cc get_default_router.c -o bin/get_default_router

bin/get_rt_table: bin/
	cc get_rt_table.c -o bin/get_rt_table

bin/bpf: bin/
	cc bpf.c -o bin/bpf


.PHONY: clear
clear:
	rm -rf bin
