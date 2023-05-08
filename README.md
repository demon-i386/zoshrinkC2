# MeliziaC2
DNS over HTTPS targeted malware (only runs once)

<p align="center">
  <img src="./logo.jpg" width="500">
</p>

## Key Features
- [x] Auto-delete malware on failure
- [x] Fully encrypted (per victim RSA key) DoH (DNS-over-HTTPS) communication
- [x] Malware only runs once!   

## Diagram

![diagram](./melizia_diagram.svg)


## Compilation
###### Static compile
```
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl

or (windows)

rustup target add x86_64-pc-windows-gnu
cargo build --release --target=x86_64-pc-windows-gnu
```
