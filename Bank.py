from dataclasses import dataclass
from getpass import getpass
from random import randrange
from secrets import randbelow
from time import sleep
from typing import Dict, Tuple, Callable, ClassVar
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

class Menu:
    MENU: ClassVar[Tuple[
        Tuple[
            str, Callable[['Menu'], bool]
        ], ...
    ]]

    def screen(self):
        prompt = '\n'.join(
            f'{i}. {name}'
            for i, (name, fun) in enumerate(self.MENU)
        ) + '\n'

        while True:
            choice = input(prompt)

            try:
                name, fun = self.MENU[int(choice)]
            except ValueError:
                print('Invalid integer entered')
            except IndexError:
                print('Choice out of range')
            else:
                if fun(self):
                    break


@dataclass
class Account(Menu):
    card: str
    pin: str
    balance: float

    @classmethod
    def generate(cls) -> 'Account':
        return cls(
            card=f'400000{randrange(1e10):010}',
            pin=f'{randbelow(10_000):04}',
            balance=0
        )

    def dump(self):
        print(
            f"Your card number: {self.card}\n"
            f"Your PIN: {self.pin}\n"
            f"Your balance: {self.balance}"
        )

    def balance(self):
        print(self.balance)

    def logout(self) -> bool:
        print('You have successfully logged out!')
        return True

    def deposit(self) -> bool:
        amount = float(input("how much money to deposit?"))
        if amount > 0:
            self.balance += amount
            # return True
        return False

    def withdraw(self) -> bool:
        amount = float(input("how much money to withdraw?"))
        if amount > self.balance or amount < 0:
            return False
        self.balance -= amount
        # return True

    def exit(self):
        print('Bye!')
        exit()

    MENU = (
        ('Exit', exit),
        ('Balance', balance),
        ('Log out', logout),
        ('deposit', deposit),
        ('withdraw', withdraw),
    )


class BankingSystem(Menu):
    def __init__(self):
        self.accounts: Dict[str, Account] = {}

    def create_account(self):
        account = Account.generate()
        print('Your card has been created')
        account.dump()
        self.accounts[account.card] = account

    def log_in(self):
        for _ in range(3):
            card = input('Enter your card number: ')
            pin = getpass('Enter your PIN: ')

            account = self.accounts.get(card)
            if account is None or account.pin != pin:
                print('Wrong card or PIN')
                sleep(2)
            else:
                print('You have successfully logged in!')
                account.screen()
                break

    def transfer(self):
        card = input('Enter your card number: ')
        pin = getpass('Enter your PIN: ')

        account1 = self.accounts.get(card)
        if account1 is None or account1.pin != pin:
            print('Wrong card or PIN')
            sleep(2)
        else:
            print('You have successfully logged in!')
            card2 = input('Enter the card number you wish to transfer money for: ')
            transfer_value = float(input("enter the amount:"))
            account2 = self.accounts.get(card2)
            if transfer_value > account1.balance or transfer_value < 0:
                print("invalid transaction")
                return False
            account1.balance -= transfer_value
            account2.balance += transfer_value
            print("You have sucessfully transfered the money. your new balance is :")
            print(account1.balance)


    def exit(self) -> bool:
        print('Bye!')
        return True


    #********************************************************** From here is for crt and connection **********************************************************
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

        # ********************************************************** Until here is for crt and connection**********************************************************









    MENU = (
        ('Exit', exit),
        ('Create an account', create_account),
        ('Log into an account', log_in),
        ('transfer money', transfer)
    )


BankingSystem().screen()