## 1. Install dependencies
- Fedora: `sudo dnf install -y clang libbpf-devel xdp-tools bpftool`
- Ubuntu: `sudo apt-get install -y clang make libbpf-dev xdp-tools`

## 2. Build
- `cd bpf_dns_blocker`
- `make`

## 3. Load the compiled eBPF program
- `sudo make load`

## To disable the program:
- `sudo make unload`
