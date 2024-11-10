import socket
import json
import base64
import random
import logging
import argparse
import socket
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


def rsa_encrypt(message, public_key):
    e, n = public_key
    message_int = int.from_bytes(message, byteorder="big")
    encrypted_message_int = pow(message_int, e, n)
    encrypted_message = encrypted_message_int.to_bytes(
        (n.bit_length() + 7) // 8, byteorder="big"
    )
    return encrypted_message


def send_packet(conn, packet):
    try:
        conn.sendall((json.dumps(packet) + "\n").encode("ascii"))
        print("Sent packet:", packet)
    except Exception as e:
        print(f"Error sending packet: {e}")


def receive_packet(conn):
    try:
        data = conn.recv(1024).decode("ascii")
        packet = json.loads(data)
        print("Received packet:", packet)
        return packet
    except ConnectionResetError as e:
        print("Connection was reset by peer:", e)
        return None
    except json.JSONDecodeError as e:
        print("Error decoding JSON:", e)
        return None


# Protocol 2 execution
def protocol_2(addr, port):
    print("Starting Protocol 2...")
    symmetric_key = bytes([random.randint(0, 255) for _ in range(16)])
    print("Generated symmetric key:", symmetric_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        try:
            conn.connect((addr, port))
            print("Connected to Bob")

            # Step 1: Request RSA Key
            send_packet(conn, {"opcode": 0, "type": "RSA"})

            # Step 2: Receive RSA public key from Bob
            rsa_packet = receive_packet(conn)
            if rsa_packet["opcode"] == 1 and rsa_packet["type"] == "RSA":
                print("Received RSA public key from Bob")
                e = rsa_packet["public"]
                n = rsa_packet["parameter"]["n"]
                public_key = (e, n)
                print("Decoded RSA public key:", public_key)

                # Encrypt symmetric key
                encrypted_key = rsa_encrypt(symmetric_key, public_key)
                encrypted_key_base64 = base64.b64encode(encrypted_key).decode("ascii")
                send_packet(
                    conn,
                    {"opcode": 2, "type": "RSA", "encryption": encrypted_key_base64},
                )
                print("Sent encrypted symmetric key to Bob")

                # Step 4: Encrypt message using AES and send to Bob
                alice_message = "Hello"
                encrypted_message = aes_encrypt(alice_message, symmetric_key)
                encrypted_message_base64 = base64.b64encode(encrypted_message).decode(
                    "ascii"
                )
                send_packet(
                    conn,
                    {
                        "opcode": 2,
                        "type": "AES",
                        "encryption": encrypted_message_base64,
                    },
                )
                print("Sent AES-encrypted message to Bob:", alice_message)

                # Step 5: Receive and decrypt response from Bob
                response_packet = receive_packet(conn)
                if (
                    response_packet
                    and response_packet.get("opcode") == 2
                    and response_packet.get("type") == "AES"
                ):
                    encrypted_response_base64 = response_packet["encryption"]
                    encrypted_response = base64.b64decode(encrypted_response_base64)
                    decrypted_message = aes_decrypt(encrypted_response, symmetric_key)
                    print(
                        "Decrypted message from Bob:",
                        decrypted_message.decode("utf-8", errors="ignore"),
                    )
            else:
                print("Did not receive expected RSA key packet from Bob")

        except ConnectionResetError:
            print("Connection was reset by Bob during communication")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("Protocol 2 completed.\n")


def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--addr",
        metavar="<bob's address>",
        help="Bob's address",
        type=str,
        required=True,
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
        help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
        type=str,
        default="INFO",
    )
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    protocol_2(args.addr, args.port)


if __name__ == "__main__":
    main()
