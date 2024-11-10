import socket
import json
import base64
import random
import logging
import argparse
import socket
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def rsa_encrypt(message, public_key):
    e, n = public_key
    message_int = int.from_bytes(message, byteorder="big")
    encrypted_message_int = pow(message_int, e, n)
    encrypted_message = encrypted_message_int.to_bytes(
        (n.bit_length() + 7) // 8, byteorder="big"
    )
    return encrypted_message


# PKCS7 패딩을 추가하는 함수
def pad(message):
    padding_length = BLOCK_SIZE - len(message) % BLOCK_SIZE
    padding = chr(padding_length) * padding_length
    return message + padding

def unpad(message):
    padding_length = ord(message[-1])
    return message[:-padding_length]

# AES 암호화 및 Base64 인코딩
def aes_encrypt(message, key):
    # AES 암호화 시 문자열을 바이트 형식으로 변환
    aes = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message).encode()  # PKCS7 패딩을 추가하고 문자열을 바이트로 인코딩
    encrypted_message = aes.encrypt(padded_message)
    return encrypted_message  # 바이트 형식의 암호문을 반환

def aes_decrypt(key, encrypted):
    # AES 복호화 시 복호화된 바이트 데이터를 문자열로 변환
    aes = AES.new(key, AES.MODE_ECB)
    decrypted_message = aes.decrypt(encrypted).decode("utf-8", errors="ignore")
    try:
        unpadded_message = unpad(decrypted_message)  # 패딩 제거
        print("AES Decrypted and unpadded message:", unpadded_message)
        return unpadded_message  # 문자열로 반환
    except ValueError as e:
        print("Error during unpadding:", e)
        return None



def send_packet(conn, packet):
    try:
        conn.sendall((json.dumps(packet) + "\n").encode("ascii"))
        print("Sent packet:", packet)
    except Exception as e:
        print(f"Error sending packet: {e}")


def receive_packet(conn):
    retry_count = 0
    max_retries = 3
    while retry_count < max_retries:
        try:
            data = conn.recv(1024).decode("ascii")
            if not data:
                print("No data received. Retrying...")
                retry_count += 1
                continue
            print("Raw received data:", data)  # 원시 데이터 로깅
            packet = json.loads(data)
            print("Received packet:", packet)
            return packet
        except ConnectionResetError as e:
            print("Connection was reset by peer:", e)
            return None
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            return None
    print("No data received. Connection may have been closed by the server.")
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
                alice_message = "Hello from Alice via AES"
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
