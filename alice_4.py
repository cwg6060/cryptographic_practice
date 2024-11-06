import json
import socket
import argparse
import logging

# 소수 여부를 판별하는 함수
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

# 유효한 생성자인지 확인하는 함수
def is_valid_generator(g, p):
    def factorize(n):
        factors = []
        i = 2
        while i * i <= n:
            while (n % i) == 0:
                factors.append(i)
                n //= i
            i += 1
        if n > 1:
            factors.append(n)
        return factors

    factors = factorize(p - 1)
    
    for q in factors:
        if pow(g, (p - 1) // q, p) == 1:
            return False
    return True

# 패킷 유효성 검사 함수
def validate_packet(packet):
    required_fields = ["opcode", "type", "public", "parameter"]
    parameter_fields = ["p", "g"]

    for field in required_fields:
        if field not in packet:
            print(f"Packet validation error: Missing field '{field}'")
            return False

    if not isinstance(packet["opcode"], int) or packet["opcode"] != 1:
        print("Packet validation error: 'opcode' should be integer 1")
        return False
    if not isinstance(packet["type"], str) or packet["type"] != "DH":
        print("Packet validation error: 'type' should be 'DH'")
        return False
    if not isinstance(packet["public"], (str, int)):
        print("Packet validation error: 'public' should be a string or integer")
        return False
    if not isinstance(packet["parameter"], dict):
        print("Packet validation error: 'parameter' should be a dictionary")
        return False
    
    for field in parameter_fields:
        if field not in packet["parameter"]:
            print(f"Packet validation error: Missing 'parameter' field '{field}'")
            return False
    
    return True

# 서버와 통신하는 함수
def communicate_with_server(addr, port):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))

    try:
        initial_message = {"opcode": 0, "type": "DH"}
        client_socket.sendall(json.dumps(initial_message).encode())
        logging.info("Sent initial message: %s", json.dumps(initial_message))

        response = client_socket.recv(1024).decode()
        received_message = json.loads(response)
        logging.info("Received message from server: %s", json.dumps(received_message))

        if not validate_packet(received_message):
            error_message = {"opcode": 3, "error": "invalid packet format"}
            logging.info("Alice response: %s", json.dumps(error_message))
            client_socket.sendall(json.dumps(error_message).encode())
            return

        p = received_message["parameter"]["p"]
        g = received_message["parameter"]["g"]

        prime_check = is_prime(p)
        generator_check = is_valid_generator(g, p) if prime_check else False

        # p가 유효하지 않은 경우
        if not prime_check:
            error_message = {"opcode": 3, "error": "incorrect prime number"}
            logging.info("Alice response: %s", json.dumps(error_message))
            client_socket.sendall(json.dumps(error_message).encode())
        # g가 유효하지 않은 경우
        elif not generator_check:
            error_message = {"opcode": 3, "error": "incorrect generator"}
            logging.info("Alice response: %s", json.dumps(error_message))
            client_socket.sendall(json.dumps(error_message).encode())
        # 둘 다 유효한 경우
        else:
            success_message = {"opcode": 2, "status": "success"}
            logging.info("Alice response: %s", json.dumps(success_message))
            client_socket.sendall(json.dumps(success_message).encode())
    
    except Exception as e:
        logging.error("Error during communication: %s", e)
    
    finally:
        client_socket.close()
        logging.info("Disconnected from server")

# 명령줄 인자 처리
def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

# 메인 함수
def main():
    args = command_line_args()
    log_level = getattr(logging, args.log.upper(), logging.INFO)
    logging.basicConfig(level=log_level)

    communicate_with_server(args.addr, args.port)

if __name__ == "__main__":
    main()

