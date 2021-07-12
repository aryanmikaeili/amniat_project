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




class Merchant:
    def __init__(self):
        self.items = {'X product': 1000, 'Y product': 2000}
        self.back_account = None
        self.username, self.CERT, self.KEY = self.start()
        self.sll_sock = None

    def add_item(self, commodity, price):
        self.items[commodity] = price

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

    def set_up_server(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port))
        s.listen(5)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        context.load_cert_chain(certfile=self.CERT, keyfile=self.KEY)

        self.sll_sock = context.wrap_socket(s, server_side=True)
        print("We are online!")

    def show_items(self, connection):
        index = 0
        for key, value in self.items.items():
            connection.send(bytes(f"item {index}: {key}, price: {value}", 'utf-8'))
            index += 1

    def run_server(self):
        while True:
            try:
                conn, add = self.sll_sock.accept()
                print(f"client {add} connected!")
                greeting = bytes(f"Hello client with {add} address! These are our items:", 'utf-8')
                selection = bytes("Please select your item (you have 5 seconds):", 'utf-8')
                index = bytes("Index:", 'utf-8')
                end = bytes("end", 'utf-8')

                conn.send(greeting)
                time.sleep(1)
                self.show_items(conn)
                time.sleep(1)
                conn.send(selection)
                time.sleep(1)
                conn.send(index)
                time.sleep(5)

                chosen_ind = int(conn.recv(4096).decode('utf-8'))
                name, val = list(self.items.keys())[chosen_ind], list(self.items.values())[chosen_ind]
                print(name, val)
                recipient = bytes(f"Your transaction for {name} with a price of {val} has started!", 'utf-8')
                conn.send(recipient)
                conn.send(end)

            except:
                print(f"something went wrong")
                continue


if __name__ == "__main__":

    IP = '127.0.0.1'
    PORT = 1251
    CERT = ''
    KEY = ''

    merchant = Merchant()
    merchant.set_up_server(IP, PORT)
    merchant.run_server()

