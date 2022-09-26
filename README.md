# CS5204_eBPF
## Dependencies
For now: (will  be updated later)
```
sudo apt-get install gpg curl tar xz make gcc flex bison libssl-dev libelf-dev llvm clang
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
