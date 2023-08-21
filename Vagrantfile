Vagrant.configure("2") do |config|

  config.vm.define "node01" do |node01|
    node01.vm.box = "bento/ubuntu-22.04"
    node01.vm.hostname = "node01"
    node01.vm.network :private_network, ip: "192.168.56.101"
  end

  config.vm.define "node02" do |node02|
    node02.vm.box = "bento/ubuntu-22.04"
    node02.vm.hostname = "node02"
    node02.vm.network :private_network, ip: "192.168.56.102"
  end

  config.vm.define "node03" do |node03|
    node03.vm.box = "bento/ubuntu-22.04"
    node03.vm.hostname = "node03"
    node03.vm.network :private_network, ip: "192.168.56.103"
  end

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  # config.vm.network "public_network"

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
  # config.vm.provider "virtualbox" do |vb|
  #   # Display the VirtualBox GUI when booting the machine
  #   vb.gui = true
  #
  #   # Customize the amount of memory on the VM:
  #   vb.memory = "1024"
  # end


  config.vm.provider :virtualbox do |vb|
    vb.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
    vb.memory = 2048
    vb.cpus = 4
  end

end
