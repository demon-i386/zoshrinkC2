# MeliziaC2
DNS over HTTPS targeted malware (only runs once)

<p align="center">
  <img src="./logo.jpg" width="500">
</p>

## Diagram

![diagram](./melizia_diagram.svg)


## Compilation
- Static compile
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl
