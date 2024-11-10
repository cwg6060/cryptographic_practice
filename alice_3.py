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
    if rmsg["opcode"] == 1 and rmsg["type"] == "DH":
        p = rmsg["parameter"]["p"]
        g = rmsg["parameter"]["g"]
        bob_public = rmsg["public"]

        # Step 3: Generate Alice's DH keypair and shared secret
        alice_private = random.randint(2, p - 1)
        alice_public = pow(g, alice_private, p)
        shared_secret = pow(bob_public, alice_private, p)

        logging.info("Computed shared secret with Bob")
        # Generate AES key from shared secret
        to_byte_shared_secret = shared_secret.to_bytes(2, byteorder="big")
        # Make 32 bytes by repeating the shared secret bytes
        aes_key = to_byte_shared_secret * 16
        # Convert Alice's DH public key to base64
        base64_alice_public = base64.b64encode(
            alice_public.to_bytes(2, byteorder="big")
        ).decode()
        # Encrypt Alice's base64-encoded public key with AES key
        encrypted_alice_public = base64.b64encode(
            encrypt(aes_key, base64_alice_public)
        ).decode()

        smsg = {"opcode": 1, "type": "DH", "public": alice_public}
        print(smsg)
        sjs = json.dumps(smsg)
        sbytes = sjs.encode("ascii")
        logging.debug("sjs: {}".format(sjs))

        logging.debug("sbytes: {}".format(sbytes))

        conn.sendall(sbytes)
        logging.info("Sent Alice's DH public key to Bob")

        rbytes = conn.recv(1024)

        rjs = rbytes.decode("ascii")

        rmsg = json.loads(rjs)
        logging.info("Received encrypted message from Bob: {}".format(rmsg))

        if rmsg["opcode"] == 2 and rmsg["type"] == "AES":
            # Step 4: Encrypt and send message to Bob
            encrypted_data = base64.b64decode(rmsg["encryption"].encode())
            decrypted = decrypt(aes_key, encrypted_data)
            logging.info("Decrypted message from Bob: {}".format(decrypted.decode()))
            message = "world"
            encrypted = encrypt(aes_key, message)
            encrypted_str = base64.b64encode(encrypted).decode()

            smsg = {"opcode": 2, "type": "AES", "encryption": encrypted_str}
            print(smsg)

            try:
                sjs = json.dumps(smsg)
            except TypeError as e:
                logging.error(f"JSON serialization error: {e}")
                # Handle error appropriately
            except Exception as e:
                logging.error(f"Unexpected error during JSON serialization: {e}")
                # Handle other errors
            sbytes = sjs.encode("ascii")
            conn.sendall(sbytes)
            logging.info("Sent encrypted message to Bob")
            conn.close()
    else:
        print("No")


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
