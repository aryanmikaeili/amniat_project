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





class BankAccount:
    """
    BankAccount Class
    """
    def __init__(self, id: int):
        self.id = id
        self.balance = 0

    def deposit(self, amount: float) -> bool:
        '''adds money to balance'''
        if amount > 0:
            self.balance += amount
            return True
        return False

    def withdraw(self, amount: float) -> bool:
        '''subtracts money from balance if funds are sufficient'''
        if amount > self.balance or amount < 0:
            return False
        self.balance -= amount
        return True

    def display_balance(self):
        """ displays current account balance """
        print(f'\nNet Available Balance is ${self.balance}')

    def connect_with_ca(self):
        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations("ca_cert.crt")
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

#
# def interface():
#     """
#     Interface for interacting with the bank account
#     """
#     print(f'Hello! Welcome to the Deposit and Withdrawal Machine {id}!')
#     while True:
#         action = input('\nWould you like to deposit (D), withdraw (W), show balance (S), or exit (E)? ').upper()
#
#         if action in "DWSE":
#             if action == "D":
#                 try:
#                     deposit_amount = float(input("How much would you like to deposit: "))
#                     if not account.deposit(deposit_amount):
#                         print("Please enter a positive number!")
#                     else:
#                         print(f"Successfully deposited {deposit_amount} into your account.")
#                 except ValueError:
#                     print("Please enter a positive number.")
#             if action == "W":
#                 try:
#                     withdraw_amount = float(input("How much would you like to withdraw: "))
#                     if not account.withdraw(withdraw_amount):
#                         print("You do not have enough money to withdraw.")
#                     else:
#                         print(f"Successfully withdraw {withdraw_amount} from your account.")
#                 except ValueError:
#                     print("Please enter a positive number.")
#             if action == "S":
#                 account.display_balance()
#             if action == "E":
#                 break

if __name__ == '__main__':
    name = input('What is your id? ')
    account = BankAccount(id)
    interface()