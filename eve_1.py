import socket
import json
import logging


# Function to compute the shared secret
def compute_shared_secret(public_key, private_key, p):
    return pow(public_key, private_key, p)


def main():
    # Set up Eve's socket to intercept communication from Alice on port 5554
    eve_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    eve_socket.bind(("127.0.0.1", 5554))  # Listen on a separate port
    eve_socket.listen(5)

    # Connect to Bob on port 5553
    bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_socket.connect(("127.0.0.1", 5555))  # Forward to Bob's port

    # Accept connection from Alice
    conn, addr = eve_socket.accept()
    logging.info(f"Eve intercepted connection from {addr}")

    # Step 1: Intercept DH parameters from Bob to Alice
    rbytes = bob_socket.recv(1024)
    rmsg = json.loads(rbytes.decode("ascii"))
    logging.info(f"Eve intercepted message from Bob: {rmsg}")

    if rmsg["opcode"] == 1 and rmsg["type"] == "DH":
        p = rmsg["parameter"]["p"]
        g = rmsg["parameter"]["g"]
        bob_public = rmsg["public"]
        logging.info(
            f"Eve obtained DH parameters p: {p}, g: {g}, bob_public: {bob_public}"
        )

    # Step 2: Intercept DH public key from Alice to Bob
    rbytes = conn.recv(1024)
    rmsg = json.loads(rbytes.decode("ascii"))
    logging.info(f"Eve intercepted message from Alice: {rmsg}")

    if rmsg["opcode"] == 1 and rmsg["type"] == "DH":
        alice_public = rmsg["public"]
        logging.info(f"Eve obtained alice_public: {alice_public}")

        # Eve now has both public keys; she can calculate the shared secret
        shared_secret = compute_shared_secret(bob_public, alice_public, p)
        logging.info(f"Eve computed shared secret: {shared_secret}")

        # Derive the AES key from the shared secret
        aes_key = (shared_secret.to_bytes(2, byteorder="big") * 16)[
            :32
        ]  # Adjust for 32-byte AES key

        # Step 3: Intercept AES encrypted message from Bob and decrypt
        rbytes = bob_socket.recv(1024)
        rmsg = json.loads(rbytes.decode("ascii"))
        logging.info(f"Eve intercepted encrypted message: {rmsg}")

        if rmsg["opcode"] == 2 and rmsg["type"] == "AES":
            encrypted_message = bytes.fromhex(rmsg["encryption"])

            # Decrypt the message
            decrypted_message = decrypt_message(encrypted_message, aes_key)
            logging.info(f"Eve decrypted message from Alice: {decrypted_message}")


def decrypt_message(encrypted_message, key):
    decrypted = bytearray()
    for i in range(len(encrypted_message)):
        decrypted.append(encrypted_message[i] ^ key[i % len(key)])
    return decrypted.decode("utf-8")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
