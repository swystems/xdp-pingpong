sudo apt update && \
sudo apt --fix-broken install && \ 
sudo apt -y install make clang gcc-multilib libbpf-dev && \
make bpftool
