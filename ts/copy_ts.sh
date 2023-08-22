vagrant ssh node01 -c "sudo cp /sys/fs/bpf/xdp_map_t1 /vagrant/ts/ts4" && \
vagrant ssh node01 -c "sudo cp /sys/fs/bpf/xdp_map_t2 /vagrant/ts/ts1" && \
vagrant ssh node03 -c "sudo cp /sys/fs/bpf/xdp_map_t1 /vagrant/ts/ts2" && \
vagrant ssh node03 -c "sudo cp /sys/fs/bpf/xdp_map_t2 /vagrant/ts/ts3"
