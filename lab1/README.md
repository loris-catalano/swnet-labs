# Lab 1 — Packet Capture and Parsing

This lab implements a simple packet sniffer that prints key information for each observed packet. It’s provided in two versions:

- C (using libpcap): live capture from a network interface and offline parsing from a `.pcap` file
- Rust (using the `pcap` crate): live capture from a network interface

Both versions print time, MAC addresses, IP addresses, protocol (TCP/UDP), and ports. The C live-capture version also inspects HTTP traffic to detect GET/POST requests and the Host header.


## C implementation (libpcap)

### Requirements
- GCC/Clang
- libpcap development files (`libpcap-dev` on Debian/Ubuntu, default on macOS)

### Build

From `lab1/c`:

```sh
gcc -o build/cap capture_and_parse.c -lpcap
```


### Run

- Live capture (replace `en0` with your interface):

```sh
sudo ./build/cap en0
```


Notes:
- Live capture prints per-packet: timestamp, source/destination MAC, source/destination IP, protocol (TCP/UDP), and ports. For TCP/80 traffic, it attempts to detect HTTP method (GET/POST) and prints the Host header when available.
- You may need to adjust the interface name (`en0` is common on macOS; use `ifconfig` to list interfaces).

---

## Rust implementation (`pcap` crate)

### Requirements

- Rust toolchain (e.g., via rustup)
- Root/sudo privileges for live capture

### Build & run

From `lab1/rust`:

```sh
# Build
cargo build

# Run (sudo often required for live capture)
sudo cargo run
```

Important:
- The current code selects the interface with name `en0`:
  - See `src/main.rs` where it filters `pcap::Device::list()` by `d.name == "en0"`.
  - If your active interface has a different name (e.g., `en1`, `bridge0`, etc.), edit `src/main.rs` accordingly.



