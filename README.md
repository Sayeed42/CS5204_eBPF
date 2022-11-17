# CS5204_eBPF
## Dependencies
For eBPF programs:
```
sudo apt-get install gpg curl tar xz-utils make gcc flex bison libssl-dev libelf-dev llvm clang libbpf-dev binutils-dev libreadline-dev
```
For kernel compilation:
```
sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison dwarves
``` 
For using QEMU:
```
sudo apt-get install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager
```

## First Stpes
To run the `minimal` example from `libbpf-bootstrap`:
```
cd
git clone https://github.com/libbpf/libbpf-bootstrap.git
cd libbpf-bootstrap/
git submodule update --init --recursive
cd examples/c/
make
sudo ./minimal
```
## Running BMC
Assuming you have installed all the dependencies mentioned [above](https://github.com/Sayeed42/CS5204_eBPF/edit/main/README.md#dependencies), run:
```
cd
git clone https://github.com/Sayeed42/bmc-cache.git
cd bmc-cache
./kernel-src-download.sh
./kernel-src-prepare.sh
cd bmc
make
```
Then, type `ip link show` to see what interfaces you have in your machine, choose one interface number, run:
```
sudo ./bmc <interface number>
```
Don't panic if it doesn't work, as long as you get the following message at the end, you are fine for now:
```
libbpf: Kernel error message: Underlying driver does not support XDP in native mode
Error: bpf_set_link_xdp_fd failed for interface <interface number>
```
It means the program is good, it passed the verifier, which means it is safe for the kernel. As far as our project is concerned, it's enough for now. To actually see it work successfully, we need to make changes in our host/VM systems, we can make that effort later.

## Compiling Linux Kernel
```
cd
git clone https://github.com/torvalds/linux.git
cd linux
git checkout v5.15
cp ~/CS5204_eBPF/q-script/.config .config
make -j$(nproc)
```

## Running the VM
```
make qscript
```

## Building and Running the ICMP servers
You can build the programs running `make` from any directory and clean the executables running `make clean` from any directory.
It is recommended to build the programs on the host and run them on the VM. After starting the VM and going into any program directory (tc_icmp/xdp_icmp), run `./script.sh` to attach the programs and `./clean.sh` to detach the programs.

## DNS Server
So far, only attaching the program and updating the directory works. Working on testing scripts to send queries and get replies.
Example attachment and update:
```
make
make qscript
cd ~/CS5204_eBPF/xdp_dns
./xdp_dns 3 &
./xdp_dns_update add a foo.bar 1.2.3.4 120
./xdp_dns_update list
./xdp_dns_update remove a foo.bar 1.2.3.4
pkill xdp_dns
^D
make clean
```
