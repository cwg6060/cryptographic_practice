import json
import socket
import threading
import argparse
import logging
import random

def is_prime_basic(n):
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

def generate_invalid_prime_with_valid_generator(start, end):
    p = random.randint(start, end)
    while is_prime_basic(p): 
        p = random.randint(start, end)
    
    g = 2 
    return p, g

def generate_valid_prime_with_invalid_generator(start, end):
    p = random.randint(start, end)
    while not is_prime_basic(p): 
        p = random.randint(start, end)
    
    g = p - 1  
    return p, g

def validate_packet(packet, expected_opcode):
    required_fields = ["opcode", "type"]
    for field in required_fields:
        if field not in packet:
            logging.error(f"Packet validation error: Missing field '{field}'")
            return False
    if packet["opcode"] != expected_opcode or packet["type"] != "DH":
        logging.error("Packet validation error: Incorrect opcode or type")
        return False
    return True

alternate_invalid_flag = 0

def handle_client(conn, addr):
    global alternate_invalid_flag
    logging.info("[*] Connected by Alice at {}:{}".format(addr[0], addr[1]))

    try:
        data = conn.recv(1024).decode()
        if not data:
            return
        initial_message = json.loads(data)
        logging.info("Received message from Alice: %s", json.dumps(initial_message))

        if not validate_packet(initial_message, expected_opcode=0):
            error_message = {"opcode": 3, "error": "invalid packet format"}
            conn.sendall(json.dumps(error_message).encode())
            logging.info("Sent error response to Alice: %s", json.dumps(error_message))
            return

        if alternate_invalid_flag % 2 == 0:
            p, g = generate_invalid_prime_with_valid_generator(400, 500)
            logging.info("Sending invalid p (non-prime) and valid g to Alice: p={}, g={}".format(p, g))
        else:
            p, g = generate_valid_prime_with_invalid_generator(400, 500)
            logging.info("Sending valid p and invalid g to Alice: p={}, g={}".format(p, g))

        alternate_invalid_flag += 1

        dh_message = {
            "opcode": 1,
            "type": "DH",
            "public": "Base64_encoded_public_key_placeholder",
            "parameter": {"p": p, "g": g}
        }
        conn.sendall(json.dumps(dh_message).encode())
        logging.info("Sent DH parameters to Alice: %s", json.dumps(dh_message))

        response = conn.recv(1024).decode()
        if response:
            alice_response = json.loads(response)
            logging.info("Received response from Alice: %s", json.dumps(alice_response))

    except Exception as e:
        logging.error("Error during communication with Alice: %s", e)
    
    finally:
        conn.close()
        logging.info("Disconnected from Alice")

def run(addr, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((addr, port))
    server_socket.listen(10)
    logging.info("[*] Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, client_addr = server_socket.accept()
        logging.info("[*] Bob accepts the connection from {}:{}".format(client_addr[0], client_addr[1]))

        conn_handle = threading.Thread(target=handle_client, args=(conn, client_addr))
        conn_handle.start()

def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's IP address>", help="Bob's IP address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's open port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

def main():
    args = command_line_args()
    log_level = getattr(logging, args.log.upper(), logging.INFO)
    logging.basicConfig(level=log_level)

    run(args.addr, args.port)

if __name__ == "__main__":
    main()
