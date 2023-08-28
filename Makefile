sec ?= xdp_pp
obj ?= xdp.o
dev ?= eth1
type ?= xdpoffload

CLANG = clang-11
OBJS = $(patsubst %.c,%.o,$(wildcard *.c))

xdp.o: xdp.c
	$(CLANG) -Wall -O2 -g -target bpf -c $< -o $@ 

all: $(OBJS)

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

userprog:
	$(CLANG) -Wall -O2 -g -lbpf -lxdp xdp_user.c -o xdp_user.o

install:
	cd ./lib/xdp-tools/ && ./configure && cd ../../
	sudo make -C ./lib/xdp-tools/lib/libxdp install -j4
	sudo make -C ./lib/xdp-tools/lib/libbpf/src install -j4
	echo "LD_LIBRARY_PATH=/usr/lib/:/usr/lib64/:/usr/local/lib:/usr/local/lib64:$LD_LIBRARY_PATH" | sudo tee -a /etc/environment
