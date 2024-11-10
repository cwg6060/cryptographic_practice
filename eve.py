import socket
import json
import logging


# Function to compute the shared secret (if needed)
def compute_shared_secret(public_key, private_key, p):
    return pow(public_key, private_key, p)


def log_message(log_data):
    with open("eve_intercepted.log", "a") as log_file:
        log_file.write(json.dumps(log_data) + "\n")


def main():
    # Set up Eve's socket to intercept communication
    eve_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    eve_socket.bind(("0.0.0.0", 5554))  # Listening on different port to intercept
    eve_socket.listen(5)

    # Accept connection from Alice
    conn, addr = eve_socket.accept()
    logging.info(f"Eve intercepted connection from {addr}")

    # Step 1: Intercept DH parameters from Bob to Alice
    rbytes = conn.recv(1024)
    rmsg = json.loads(rbytes.decode("ascii"))
    logging.info(f"Eve intercepted message from Bob: {rmsg}")

    if rmsg["opcode"] == 1 and rmsg["type"] == "DH":
        log_data = {
            "opcode": rmsg["opcode"],
            "type": rmsg["type"],
            "public": rmsg["public"],
            "parameter": rmsg.get("parameter"),
        }
        log_message(log_data)

    # Step 2: Intercept DH public key from Alice to Bob
    rbytes = conn.recv(1024)
    rmsg = json.loads(rbytes.decode("ascii"))
    logging.info(f"Eve intercepted message from Alice: {rmsg}")

    if rmsg["opcode"] == 1 and rmsg["type"] == "DH":
        log_data = {
            "opcode": rmsg["opcode"],
            "type": rmsg["type"],
            "public": rmsg["public"],
        }
        log_message(log_data)

    # Step 3: Intercept AES encrypted message from Bob
    rbytes = conn.recv(1024)
    rmsg = json.loads(rbytes.decode("ascii"))
    logging.info(f"Eve intercepted encrypted message: {rmsg}")

    if rmsg["opcode"] == 2 and rmsg["type"] == "AES":
        log_data = {
            "opcode": rmsg["opcode"],
            "type": rmsg["type"],
            "encryption": rmsg["encryption"],
        }
        log_message(log_data)


def decrypt_message(encrypted_message, key):
    decrypted = bytearray()
    for i in range(len(encrypted_message)):
        decrypted.append(encrypted_message[i] ^ key[i % len(key)])
    return decrypted.decode("utf-8")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
