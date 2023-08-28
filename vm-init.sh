sudo apt update
sudo apt --fix-broken install 
sudo apt -y install make clang-11 gcc-multilib libpcap-dev pkg-config libelf-dev m4
make bpftool
make install
