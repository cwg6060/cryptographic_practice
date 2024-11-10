import json
import base64
import logging
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def pad(msg):
    pad_len = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)
    return msg + chr(pad_len) * pad_len


def unpad(msg):
    pad_len = ord(msg[-1])
    return msg[:-pad_len]


def decrypt(key, encrypted):
    aes = AES.new(key, AES.MODE_ECB)
    decrypted = aes.decrypt(encrypted)
    return decrypted.decode()


def read_packets(packet_filename):
    with open(packet_filename, "r") as f:
        lines = f.readlines()
        lines = [line.strip() for line in lines if line.strip()]
        packets = [json.loads(line) for line in lines]
    return packets


def reconstruct_and_decrypt(packets):
    p = None
    g = None
    alice_public = None
    bob_public = None
    shared_secret = None
    decrypted_messages = []

    for packet in packets:
        opcode = packet.get("opcode")
        packet_type = packet.get("type")

        if opcode == 0 and packet_type == "DH":
            logging.info("Initial DH request")
            continue
        elif opcode == 1 and packet_type == "DH":
            parameters = packet.get("parameter", {})
            if "p" in parameters and "g" in parameters:
                p = parameters["p"]
                g = parameters["g"]
                bob_public = packet["public"]
                logging.info(
                    f"Received DH parameters: p={p}, g={g}, Bob's public={bob_public}"
                )
            else:
                alice_public = packet["public"]
                logging.info(f"Received Alice's public key: {alice_public}")
        elif opcode == 2 and packet_type == "AES":
            encryption = packet["encryption"]
            if shared_secret is None:
                if (
                    p is not None
                    and alice_public is not None
                    and bob_public is not None
                ):
                    shared_secret = compute_shared_secret(
                        p, g, alice_public, bob_public
                    )
                    if shared_secret is None:
                        logging.error("Failed to compute shared secret.")
                        return
                    logging.info(f"Computed shared secret: {shared_secret}")
                    to_byte_shared_secret = shared_secret.to_bytes(2, byteorder="big")
                    aes_key = to_byte_shared_secret * 16
                else:
                    logging.error("Insufficient data to compute shared secret.")
                    return
            encrypted_data = base64.b64decode(encryption.encode())
            decrypted_data = decrypt(aes_key, encrypted_data)
            message = unpad(decrypted_data)
            decrypted_messages.append(message)
            logging.info(f"Decrypted message: {message}")
    return decrypted_messages


def compute_shared_secret(p, g, alice_public, bob_public):
    logging.info("Attempting to compute private keys via brute-force...")
    for possible_private in range(2, p - 1):
        if pow(g, possible_private, p) == alice_public:
            alice_private = possible_private
            logging.info(f"Found Alice's private key: {alice_private}")
            shared_secret = pow(bob_public, alice_private, p)
            return shared_secret
        if pow(g, possible_private, p) == bob_public:
            bob_private = possible_private
            logging.info(f"Found Bob's private key: {bob_private}")
            shared_secret = pow(alice_public, bob_private, p)
            return shared_secret
    logging.error("Failed to find private keys.")
    return None


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--file",
        metavar="<Example packet filename>",
        default="./adv_protocol_three.log",
        type=str,
    )
    parser.add_argument(
        "-l",
        "--log",
        metavar="<log level>",
        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
        type=str,
        default="INFO",
    )
    args = parser.parse_args()
    logging.basicConfig(level=args.log.upper())

    packets = read_packets(args.file)
    decrypted_messages = reconstruct_and_decrypt(packets)

    print("\nDecrypted Messages:")
    for idx, msg in enumerate(decrypted_messages, 1):
        print(f"Message {idx}: {msg}")


if __name__ == "__main__":
    main()
