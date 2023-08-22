# How to benchmark XDP with Vagrant nodes

## Steps
The steps assume the machine is provisioned with the correct tools and dependencies. `vm-init.sh` can be used to setup a machine with the required dependencies.
Linux installed in the machines must be compiled with BPF support enabled. The testing was done using Linux 6.4.2.

### Bpftool
To have a backward-compatible XDP program, bpftool is used to handle the XDP program insertion.
- Install bpftool: `make bpftool`
- Verify that the tool is installed: `bpftool version`

### CPU isolation
In order to achieve lower jitter, a cpu should be dedicated just for the packets handling.
- Verify the number of available CPUs: `grep -c proc /proc/cpuinfo`
- Edit the file `/etc/default/grub`, adding `isolcpus=<0-indexed cpu to isolate>` to `GRUB_CMDLINE_LINUX`
- Update the grub configuration with `sudo update-grub`
- Restart the machine

### CPU affinity
In order to allow the packet handling to only happen on the dedicated cpu, the following steps are required:
- Display the interrupts and the CPUs that handle them: `sudo cat /proc/interrupts`
- Find the irq id of the network device that will handle the packets with the XDP filter
- As root, set the irq cpu affinity with: `echo <isolated cpu> > /proc/irq/<irq id of the network interface>/smp_affinity`
  - For example, if the isolated cpu has index `0` and the irq id is `5` the command will be `echo 0 > /proc/irq/5/smp_affinity`
Once this steps are completed, every XDP filter on that specific network interface will be run on the specified CPU;
since the CPU is isolated, it will also have very little "competition"

### XDP program setup
- In the root folder of the project, compile the XDP program using `make`.
- In both nodes, insert the program on the network device: `sudo make ins dev=<network interface name>`
  - The XDP program will be inserted; it can be checked by running `ip link show <network device name>` as it should appear in the list.
  - In the project vagrant configuration, the device is `eth1`

### Start the ping pong app
Once the XDP program is executed, it will start keep redirecting the same packet between the two nodes.
However, the program must be executed; XDP is triggered on receive, but there must be an initial sent packet.

- In `node02`, send a UDP packet to node01 `echo -n "payload" | nc -u w0 192.168.56.101 1235`
  - Port must be `1235`, in order to let the XDP program recognize that it is the "trigger" packet. This way, its timestamp won't be stored.
- The ping pong will execute for 2^10 rounds, at the end it will print "Done" in the log.
  - The log can be checked with `make dmesg`

### Analyze the results
Technically, the timestamps stored in the XDP program can be accessed programmatically. However, for sake of simplicity, the debug log files of the XDP can be used.
These files can be found in `/sys/fs/bpf/tc/globals/` of each node. To make the analysis easier, the `copy_ts.sh` script can be used.

The data is stored in the form of 4 timestamps:
- Timestamp 1 (`ts1`): packet is sent by node01
- Timestamp 2 (`ts2`): packet is received by node02
- Timestamp 3 (`ts3`): packet is sent by node02
- Timestamp 4 (`ts4`): packet is received by node01

For each ping-pong "round", the delay is computed as $\frac{(ts4-ts1) - (ts3-ts2)}{2}$.

The following steps allow to retrieve the results from the nodes, analyze them and plot them.

- In the `ts/` folder, retrieve the timestamp files by executing `copy_ts.sh`
- The xdp map files must be reformatted with: `python3 format.py ts1 ts2 ts3 ts4`
- Compute the delay in communication between the nodes with `python3 format.py ts1.out ts2.out ts3.out ts4.out`
  - A `res.out` file will be generated, containing the average delay for each message exchange.
- The results can be displayed with `python3 plot.py res.out`

## Resources 
https://unix.stackexchange.com/questions/326579/how-to-ensure-exclusive-cpu-availability-for-a-running-process
https://lserinol.blogspot.com/2009/02/irq-affinity-in-linux.html
