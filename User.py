import socket
import ssl
import time

import pprint
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import OpenSSL
import pickle
import os as os

HEADERSIZE = 64

CA_IP = '127.0.0.1'
CA_PORT = 2500


def send_message(socket, msg):
    message_len = f"{len(msg):<{HEADERSIZE}}"
    message_len = bytes(message_len, 'utf-8')
    socket.send(message_len)
    socket.send(msg)


class User:
    def __init__(self):
        self.bought_items = {'nothing': 0}
        self.bank_account = None
        self.bitcoin_account = None
        self.balance = 1000000
        self.username, self.CERT, self.KEY = self.start()
        self.sll_sock = None

    def connect_with_ca(self):
        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations("ca_cert.pem")
        sock = socket.create_connection((CA_IP, CA_PORT))
        ssock = context.wrap_socket(sock, server_hostname='CA_SERVER')

        print('connected with CA server!')
        return ssock

    def make_cert(self, hostname):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

        alt_names = [x509.DNSName(hostname)]
        alt_names.append(x509.DNSName(IP))

        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(1000)
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=365))
                .sign(key, hashes.SHA256(), default_backend())
        )
        client_pem = cert.public_bytes(serialization.Encoding.DER)
        return client_pem, key

    def recv_cert(self, socket):
        message_len = socket.recv(HEADERSIZE).decode('utf-8')
        message_len = int(message_len)
        msg = socket.recv(message_len)
        return msg

    def start(self):
        username = input('Enter username: ')

        cert_file_name = f"{username}_cert.crt"
        key_file_name = f"{username}_key.key"

        # key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        # p = OpenSSL.crypto.x509.load_der_x509_certificate(ssock.getpeercert(1)).public_key()
        if os.path.isfile(cert_file_name) and os.path.isfile(key_file_name):
            print('certificate already issued')
            return username, cert_file_name, key_file_name

        print(f'acquiring certificate from CA')
        ssock = self.connect_with_ca()
        cert, key = self.make_cert(username)
        send_message(ssock, cert)
        cert = self.recv_cert(ssock)
        cert = x509.load_der_x509_certificate(cert, default_backend())

        cert = cert.public_bytes(encoding=serialization.Encoding.PEM)

        print(f'certificate recieved successfully')

        key = key.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                encryption_algorithm=serialization.NoEncryption()
                                )

        with open(key_file_name, 'wb') as key_file:
            key_file.write(key)

        with open(cert_file_name, 'wb') as crt_file:
            crt_file.write(cert)

        print('closing connection with CA')
        ssock.close()
        return username, cert_file_name, key_file_name

    def connect_to_merchant(self, ip, port, merchant_crt, merchant_hostname):

        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(merchant_crt)
        sock = socket.create_connection((ip, port))
        self.sll_sock = context.wrap_socket(sock, server_hostname=merchant_hostname)
        print('connected with Merchant server!')

    def start_communicate_merchant(self):
        while True:
            rcv_msg = self.sll_sock.recv(4096).decode('utf-8')
            print(rcv_msg)
            if rcv_msg == 'Index:':
                user_inp = int(input())
                self.sll_sock.send(bytes(str(user_inp), 'utf-8'))
            if rcv_msg == 'end':
                break


if __name__ == "__main__":

    IP = '127.0.0.1'
    PORT = 1251
    CA_CERT = 'ca_cert.pem'
    KEY = ''

    user = User()
    user.connect_to_merchant(IP, PORT, CA_CERT, 'merchant1')
    user.start_communicate_merchant()
