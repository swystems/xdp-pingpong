sec ?= xdp_pp 
obj ?= xdp.o		
dev ?= eth1
type ?= xdpoffload

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

%_xdp.o: %_xdp.c
	clang -Wall -O2 -g -target bpf -c $< -o $@

all: $(OBJS)

pp_client_udp.o: pp_client_udp.c
	gcc $< -o $@
	chmod +x $@

clean:
	rm -f *.o

load:
	sudo bpftool prog load $(obj) /sys/fs/bpf/$(sec) type xdp

ins: rm load
	sudo bpftool net attach $(type) name xdp_prog dev $(dev)

insgeneric: rm load
	sudo bpftool net attach xdp name xdp_prog dev $(dev)

rm:
	sudo bpftool net detach xdp dev $(dev) 2>/dev/null || true
	sudo rm -rf /sys/fs/bpf/$(sec)

dmesg:
	sudo cat  /sys/kernel/debug/tracing/trace_pipe

dump:
	sudo ./bpftool map dump id $(id)

list:
	sudo ./bpftool map list

bpftool:
	wget https://github.com/libbpf/bpftool/releases/download/v7.2.0/bpftool-v7.2.0-amd64.tar.gz
	tar -xf bpftool-v7.2.0-amd64.tar.gz
	chmod +x bpftool
	sudo mv bpftool /usr/bin/
	rm bpftool-v7.2.0-amd64.tar.gz
