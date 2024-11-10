# BY 이서영 -> 이거 깃에서는 기록 남으니까 안 써도 되나..? 일단 오류있거나 최종 아닐수도 있으니까 써둠
import socket
import argparse
import logging
import json
import random
from Crypto.Cipher import AES
import base64

BLOCK_SIZE = 16


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

    # Step 1: Send initial DH message to Bob
    smsg = {"opcode": 0, "type": "DH"}
    sjs = json.dumps(smsg)
    sbytes = sjs.encode("ascii")
    conn.sendall(sbytes)
    logging.info("Sent initial DH message to Bob")

    # Step 2: Receive Bob's DH parameters and public key
    rbytes = conn.recv(1024)
    rjs = rbytes.decode("ascii")
    rmsg = json.loads(rjs)
    logging.info("Received DH parameters from Bob: {}".format(rmsg))

    p = rmsg["parameter"]["p"]
    g = rmsg["parameter"]["g"]
    bob_public_base64 = rmsg["public"]
    bob_public_encrypted = base64.b64decode(bob_public_base64)
    bob_public = decrypt(shared_secret, bob_public_encrypted)
    decrypted = bob_public[0 : -ord(bob_public[-1])]

    # Step 3: Generate Alice's DH keypair and shared secret
    alice_private = random.randint(2, p - 1)
    alice_public = pow(g, alice_private, p)
    shared_secret = pow(decrypted, alice_private, p)
    logging.info("Computed shared secret with Bob")

    # Generate AES key from shared secret
    shared_secret_base64 = base64.b64encode(shared_secret).decode()
    secret_bytes = shared_secret_base64.encode()
    aes_key = secret_bytes * 16  # Adjust key length as needed

    # Step 4: Encrypt and send message to Bob
    message = "hello"
    encrypted = encrypt(aes_key, message)
    encrypted_str = base64.b64encode(encrypted).decode()
    smsg = {
        "opcode": 2,
        "type": "AES",
        "public": alice_public,
        "encryption": encrypted_str,
    }

    sjs = json.dumps(smsg)
    sbytes = sjs.encode("ascii")
    conn.sendall(sbytes)
    logging.info("Sent encrypted message to Bob")

    # Step 5: Receive and decrypt Bob's response
    rbytes = conn.recv(1024)
    rjs = rbytes.decode("ascii")
    rmsg = json.loads(rjs)
    logging.info("Received encrypted response from Bob: {}".format(rmsg))

    encrypted_data = base64.b64decode(rmsg["encryption"].encode())
    decrypted = decrypt(aes_key, encrypted_data)
    decrypted_str = decrypted.decode("utf-8")
    logging.info("Decrypted message from Bob: {}".format(decrypted_str))

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
