vagrant ssh node01 -c "sudo cp /sys/fs/bpf/tc/globals/xdp_map_t1 /vagrant/xlane-xdp/ts/ts4" && \
vagrant ssh node01 -c "sudo cp /sys/fs/bpf/tc/globals/xdp_map_t2 /vagrant/xlane-xdp/ts/ts1" && \
vagrant ssh node02 -c "sudo cp /sys/fs/bpf/tc/globals/xdp_map_t1 /vagrant/xlane-xdp/ts/ts2" && \
vagrant ssh node02 -c "sudo cp /sys/fs/bpf/tc/globals/xdp_map_t2 /vagrant/xlane-xdp/ts/ts3"
