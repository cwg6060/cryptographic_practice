#BY 이서영 -> 이거 깃에서는 기록 남으니까 안 써도 되나..? 일단 오류있거나 최종 아닐수도 있으니까 써둠
import socket
import argparse
import logging
import json
import random


def run(addr, port):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    # Step 1: Send initial DH message to Bob
    initial_message = {"opcode": 0, "type": "DH"}
    conn.sendall(json.dumps(initial_message).encode())
    logging.info("Sent initial DH message to Bob")

    # Step 2: Receive Bob's DH parameters and public key
    response = conn.recv(1024).decode()
    rmsg = json.loads(response)
    logging.info("Received DH parameters from Bob: {}".format(rmsg))

    p = rmsg["parameter"]["p"]
    g = rmsg["parameter"]["g"]
    bob_public = rmsg["public"]

    # Step 3: Generate Alice's DH keypair and shared secret
    alice_private = random.randint(2, p - 1)
    alice_public = pow(g, alice_private, p)
    shared_secret = pow(bob_public, alice_private, p)
    logging.info("Computed shared secret with Bob")

    # Generate AES key from shared secret
    secret_bytes = shared_secret.to_bytes(2, byteorder="big")
    aes_key = secret_bytes * 16  # Adjust key length as needed

    # Step 4: Encrypt and send message to Bob
    message = "hello"
    encrypted = bytearray()
    for i in range(len(message)):
        encrypted.append(ord(message[i]) ^ aes_key[i % len(aes_key)])
    encrypted_str = "".join([format(b, "02x") for b in encrypted])

    smsg = {
        "opcode": 2,
        "type": "AES",
        "public": alice_public,
        "encryption": encrypted_str,
    }
    conn.send(json.dumps(smsg).encode("ascii"))
    logging.info("Sent encrypted message to Bob")

    # Step 5: Receive and decrypt Bob's response
    response = conn.recv(1024).decode()
    rmsg = json.loads(response)
    logging.info("Received encrypted response from Bob: {}".format(rmsg))

    encrypted_data = bytes.fromhex(rmsg["encryption"])
    decrypted = ""
    for i in range(len(encrypted_data)):
        decrypted += chr(encrypted_data[i] ^ aes_key[i % len(aes_key)])
    logging.info("Decrypted message from Bob: {}".format(decrypted))

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
