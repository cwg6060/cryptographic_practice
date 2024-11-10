import socket
import argparse
import logging
import json
import random
import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def unpad(message):
    padding_length = ord(message[-1])
    return message[:-padding_length]


def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)


def encrypt(key, msg):
    pad = BLOCK_SIZE - len(msg)
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())


def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    # Step 1: Request RSA public key from Bob
    smsg = {"opcode": 0, "type": "RSA"}
    sjs = json.dumps(smsg)
    conn.send(sjs.encode("ascii"))
    logging.info("Requested RSA public key from Bob")

    # Receive RSA public key from Bob
    rbytes = conn.recv(1024)
    rjs = rbytes.decode("ascii")
    rmsg = json.loads(rjs)
    logging.info("Received RSA public key from Bob: {}".format(rmsg))

    if rmsg["opcode"] == 1 and rmsg["type"] == "RSA":
        n = rmsg["parameter"]["n"]
        e = rmsg["public"]

        # Step 2: Generate symmetric key and encrypt with RSA
        symmetric_key = random.getrandbits(256).to_bytes(32, byteorder="big")
        encrypted_key = []
        for byte in symmetric_key:
            encrypted_byte = pow(byte, e, n)
            encrypted_key.append(encrypted_byte)

        # Send encrypted symmetric key to Bob
        smsg = {"opcode": 2, "type": "RSA", "encrypted_key": encrypted_key}
        print(smsg)
        sjs = json.dumps(smsg)

        conn.send(sjs.encode("ascii"))
        logging.info("Sent RSA-encrypted symmetric key to Bob")

        rbytes = conn.recv(1024)
        rjs = rbytes.decode("ascii")
        rmsg = json.loads(rjs)
        logging.info("Received RSA-encrypted symmetric key from Bob: {}".format(rmsg))

        encrypted_data = base64.b64decode(rmsg["encryption"].encode())
        decrypted = decrypt(symmetric_key, encrypted_data).decode()
        unpadded_message = unpad(decrypted)
        logging.info("Decrypted message from Bob: {}".format(unpadded_message))

        # Step 3: AES Message Exchange
        # Encrypt the message with AES and send it
        message = "hello"
        encrypted_message = encrypt(symmetric_key, message)
        base64_encrypted_message = base64.b64encode(encrypted_message).decode()

        # Send AES-encrypted message to Bob
        smsg = {"opcode": 2, "type": "AES", "encryption": base64_encrypted_message}
        print(smsg)
        sjs = json.dumps(smsg)
        conn.send(sjs.encode("ascii"))
        logging.info("Sent AES-encrypted message to Bob")
    # Close connection
    conn.close()


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
