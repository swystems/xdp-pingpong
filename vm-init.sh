cd ~ && \
  sudo apt update && \
  sudo apt --fix-broken install && \ 
  sudo apt install -y bc bison curl clang fish flex git make libelf-dev ccache libssl-dev && \
  sudo apt install -y clang llvm libelf-dev libpcap-dev gcc-multilib build-essential libbpf-dev linux-headers-generic net-tools

