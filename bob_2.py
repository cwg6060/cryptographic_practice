import socket
import argparse
import logging
import json
import random
import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def pad(message):
    padding_length = BLOCK_SIZE - len(message) % BLOCK_SIZE
    return message + chr(padding_length) * padding_length


def unpad(message):
    padding_length = ord(message[-1])
    return message[:-padding_length]


def decrypt_aes(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)


def encrypt_aes(key, msg):
    padded_msg = pad(msg)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(padded_msg.encode())


def gen_RSA():
    def gen_prime():
        while True:
            p = random.randint(400, 500)
            if all(p % i != 0 for i in range(2, int(p**0.5) + 1)):
                return p

    p = gen_prime()
    q = gen_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    d = pow(e, -1, phi)
    return p, q, e, d, n


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def run(addr, port):
    # Create socket and setup connection
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((addr, port))
    server_socket.listen(1)
    logging.info("Bob is waiting for connection on {}:{}".format(addr, port))

    # Accept connection
    conn, _ = server_socket.accept()
    logging.info("Alice is connected")

    # Generate RSA keys
    p, q, e, d, n = gen_RSA()

    # Receive initial request from Alice
    rbytes = conn.recv(1024)
    rjs = rbytes.decode("ascii")
    rmsg = json.loads(rjs)

    # Step 1: Send RSA public key to Alice
    smsg = {"opcode": 1, "type": "RSA", "public": e, "parameter": {"n": n}}
    sjs = json.dumps(smsg)
    conn.send(sjs.encode("ascii"))
    logging.info("Sent RSA public key to Alice")

    # Step 2: Receive and decrypt symmetric key
    rbytes = conn.recv(1024)
    rjs = rbytes.decode("ascii")
    rmsg = json.loads(rjs)
    logging.info("Received RSA-encrypted symmetric key from Alice: {}".format(rmsg))

    if rmsg["opcode"] == 2 and rmsg["type"] == "RSA":
        encrypted_key = rmsg["encrypted_key"]
        symmetric_key = bytearray()
        for encrypted_byte in encrypted_key:
            decrypted_byte = pow(encrypted_byte, d, n)
            symmetric_key.append(decrypted_byte)

        # Step 3: Process message with AES
        message = "world"
        encrypted_message = encrypt_aes(symmetric_key, message)
        base64_encrypted_message = base64.b64encode(encrypted_message).decode()

        # Send AES encrypted message to Alice
        smsg = {"opcode": 2, "type": "AES", "encryption": base64_encrypted_message}
        sjs = json.dumps(smsg)
        conn.send(sjs.encode("ascii"))
        logging.info("Sent AES-encrypted message to Alice")

    # Receive and decrypt encrypted message from Alice
    rbytes = conn.recv(1024)
    rjs = rbytes.decode("ascii")
    rmsg = json.loads(rjs)
    logging.info("Received AES-encrypted message from Alice: {}".format(rmsg))

    if rmsg["opcode"] == 2 and rmsg["type"] == "AES":
        encrypted_data = base64.b64decode(rmsg["encryption"])
        decrypted = decrypt_aes(symmetric_key, encrypted_data).decode()
        unpadded_message = unpad(decrypted)
        logging.info("Decrypted message from Alice: {}".format(unpadded_message))

    # Close connections
    conn.close()
    server_socket.close()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<Bob's address>",
        help="Bob's address",
        type=str,
        required=True,
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<Bob's port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>",
        help="Log level",
        type=str,
        default="INFO",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = command_line_args()
    logging.basicConfig(level=args.log.upper())
    run(args.addr, args.port)
