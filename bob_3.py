#BY 이서영 -> 이거 깃에서는 기록 남으니까 안 써도 되나..? 일단 오류있거나 최종 아닐수도 있으니까 써둠

import socket
import threading
import argparse
import logging
import json
import random


def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
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

            # Step 3: Send public key and parameters to Alice
            smsg = {
                "opcode": 1,
                "type": "DH",
                "public": bob_public,
                "parameter": {"p": p, "g": g},
            }
            conn.sendall(json.dumps(smsg).encode())
            logging.info("Sent DH parameters and public key to Alice: {}".format(smsg))

            # Step 4-5: Receive encrypted message from Alice
            rbytes = conn.recv(1024)
            rmsg = json.loads(rbytes.decode("ascii"))
            logging.info("Received encrypted message from Alice: {}".format(rmsg))

            if rmsg["opcode"] == 2 and rmsg["type"] == "AES":
                alice_public = rmsg["public"]
                shared_secret = pow(alice_public, bob_private, p)

                # Generate AES key
                secret_bytes = shared_secret.to_bytes(2, byteorder="big")
                aes_key = secret_bytes * 16  # Adjust key length as needed

                # Decrypt Alice's message using XOR
                encrypted = bytes.fromhex(rmsg["encryption"])
                decrypted = ""
                for i in range(len(encrypted)):
                    decrypted += chr(encrypted[i] ^ aes_key[i % len(aes_key)])
                logging.info("Decrypted message from Alice: {}".format(decrypted))

                # Encrypt and send response
                response = "world"
                encrypted = bytearray()
                for i in range(len(response)):
                    encrypted.append(ord(response[i]) ^ aes_key[i % len(aes_key)])
                encrypted_str = "".join([format(b, "02x") for b in encrypted])

                smsg = {"opcode": 2, "type": "AES", "encryption": encrypted_str}
                conn.send(json.dumps(smsg).encode("ascii"))
                logging.info("Sent encrypted response to Alice: {}".format(smsg))
            else:
                logging.error("Unexpected message type from Alice")

    except Exception as e:
        logging.error("Error during handling DH protocol: {}".format(e))
    finally:
        conn.close()
        logging.info("Disconnected from Alice")


def run(addr, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((addr, port))
    server_socket.listen(5)
    logging.info("Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, client_addr = server_socket.accept()
        logging.info(
            "Accepted connection from {}:{}".format(client_addr[0], client_addr[1])
        )
        thread = threading.Thread(target=handle_client, args=(conn,))
        thread.start()


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<Bob's IP address>",
        help="Bob's IP address",
        type=str,
        default="0.0.0.0",
    )
    parser.add_argument(
        "-p",
        "--port",
        metavar="<Bob's open port>",
        help="Bob's port",
        type=int,
        required=True,
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="<log level>",
        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
        type=str,
        default="INFO",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = command_line_args()
    logging.basicConfig(level=args.log.upper())
    run(args.addr, args.port)
