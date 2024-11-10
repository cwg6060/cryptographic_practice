import socket
import threading
import argparse
import logging
import json
import random
import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def encrypt(key, msg):
    pad = BLOCK_SIZE - len(msg)
    msg = msg + pad * chr(pad)
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(msg.encode())


def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(encrypted)


def is_prime(n):
    if n < 400 or n > 500:  # Check prime range
        return False
    if n < 2:
        return False
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


def gen_prime():
    while True:
        p = random.randint(400, 500)
        if is_prime(p):
            return p


def handle_client(conn):
    try:
        # Step 1: Receive initial DH message from Alice
        rbytes = conn.recv(1024)
        rmsg = json.loads(rbytes.decode("ascii"))
        logging.info("Received initial DH request from Alice: {}".format(rmsg))

        if rmsg["opcode"] == 0 and rmsg["type"] == "DH":
            # Step 2: Generate DH parameters and keypair
            p = gen_prime()
            g = random.randint(2, p - 1)
            bob_private = random.randint(2, p - 1)
            bob_public = pow(g, bob_private, p)

            # Send parameters and public key to Alice
            smsg = {
                "opcode": 1,
                "type": "DH",
                "parameter": {"p": p, "g": g},
                "public": bob_public,
            }
            conn.send(json.dumps(smsg).encode("ascii"))
            logging.info("Sent DH parameters and public key to Alice")

            # Step 3: Receive Alice's public key
            rbytes = conn.recv(1024)
            rmsg = json.loads(rbytes.decode("ascii"))

            if rmsg["opcode"] == 1 and rmsg["type"] == "DH":
                alice_public = rmsg["public"]

                # Compute shared secret
                shared_secret = pow(alice_public, bob_private, p)
                to_byte_shared_secret = shared_secret.to_bytes(2, byteorder="big")
                aes_key = to_byte_shared_secret * 16

                # Step 4: Encrypt and send message
                message = "hello"
                encrypted = encrypt(aes_key, message)
                encrypted_str = base64.b64encode(encrypted).decode()

                smsg = {"opcode": 2, "type": "AES", "encryption": encrypted_str}
                conn.send(json.dumps(smsg).encode("ascii"))
                logging.info("Sent encrypted message to Alice")

                # Step 5: Receive and decrypt Alice's response
                rbytes = conn.recv(1024)
                rmsg = json.loads(rbytes.decode("ascii"))

                if rmsg["opcode"] == 2 and rmsg["type"] == "AES":
                    encrypted_data = base64.b64decode(rmsg["encryption"].encode())
                    decrypted = decrypt(aes_key, encrypted_data)
                    logging.info(
                        "Decrypted message from Alice: {}".format(decrypted.decode())
                    )

    except Exception as e:
        logging.error("Error handling client: {}".format(e))
    finally:
        conn.close()


def run(addr, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((addr, port))
    server.listen(5)
    logging.info("Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, addr = server.accept()
        logging.info("Accepted connection from {}:{}".format(addr[0], addr[1]))
        client_thread = threading.Thread(target=handle_client, args=(conn,))
        client_thread.start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's address>",
        help="Bob's address",
        type=str,
        default="0.0.0.0",
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<bob's port>",
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
