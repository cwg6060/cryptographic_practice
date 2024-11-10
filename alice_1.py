import socket
import argparse
import logging
import json
import random
import base64

import sys

sys.set_int_max_str_digits(100000000)


def run(addr, port, number):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((addr, port))
    logging.info("Alice is connected to {}:{}".format(addr, port))
    if number == 1:
        smsg = {}
        smsg["opcode"] = 0
        smsg["type"] = "RSAKey"
        logging.debug("smsg: {}".format(smsg))

        sjs = json.dumps(smsg)
        logging.debug("sjs: {}".format(sjs))

        sbytes = sjs.encode("ascii")
        logging.debug("sbytes: {}".format(sbytes))

        conn.send(sbytes)
        logging.info("[*] Sent: {}".format(sjs))

        rbytes = conn.recv(1024)
        logging.debug("rbytes: {}".format(rbytes))

        rjs = rbytes.decode("ascii")
        logging.debug("rjs: {}".format(rjs))

        rmsg = json.loads(rjs)
        logging.debug("rmsg: {}".format(rmsg))

        def is_prime(n):
            if n % 2 == 0:
                return False
            for i in range(3, int(n**0.5) + 1, 2):
                if n % i == 0:
                    return False
            return True

        def prime_check(p, q):
            if is_prime(p) and is_prime(q):
                return True
            else:
                return False

        def verify_RSA(p, q, e, d):
            n = p * q
            phi = (p - 1) * (q - 1)
            if (e * d) % phi == 1:
                return True
            else:
                return False

        if rmsg["type"] == "RSAKey" and rmsg["opcode"] == 0:
            p = rmsg["parameter"]["p"]
            q = rmsg["parameter"]["q"]
            e = rmsg["public"]
            d = rmsg["private"]

            if prime_check(p, q) and verify_RSA(p, q, e, d):
                logging.info("Alice verified that Bob's RSA key is valid")
                logging.info("p: {}".format(p))
                logging.info("q: {}".format(q))
                logging.info("e: {}".format(e))
                logging.info("d: {}".format(d))
            else:
                logging.error("Alice verified that Bob's RSA key is invalid")

        conn.close()


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
    parser.add_argument(
        "-n",
        "--number",
        metavar="<number of protocol>",
        help="Number of protocol",
        type=int,
        default=1,
    )
    args = parser.parse_args()
    return args


def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)

    run(args.addr, args.port, args.number)


if __name__ == "__main__":
    main()
