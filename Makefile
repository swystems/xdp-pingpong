sec ?= xdp_pp
obj ?= xdp.o
dev ?= eth1

OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

%.o: %.c
	clang -Wall -O2 -g -target bpf -c $< -o $@

all: $(OBJS)

clean:
	rm -f *.o

insert:
	sudo ip link set $(dev) xdp obj $(obj) sec $(sec)

ins:
	sudo ip link set $(dev) xdpgeneric obj xdp.o sec xdp_pp

rm:
	sudo ip link set $(dev) xdpgeneric off

dmesg:
	sudo cat  /sys/kernel/debug/tracing/trace_pipe

dump:
	sudo ./bpftool map dump id $(id)

list:
	sudo ./bpftool map list

analysis:
	c++ -O2 -g -lbpf -lelf analysis.c -o analysis
