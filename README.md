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
Will be updated soon!
```
git clone https://github.com/Orange-OpenSource/bmc-cache.git
```
