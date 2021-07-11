import socket, ssl
import pprint
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

IP = '127.0.0.1'
PORT = 1251

def connect_with_ca():
    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations("ca_cert.crt")
    sock = socket.create_connection((IP, PORT))
    ssock = context.wrap_socket(sock, server_hostname='CA_SERVER')
    print('connected with CA server!')
    return ssock


def start():
    username = input('Enter username: ')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    ssock = connect_with_ca()
    pem = key.public_key().public_bytes(encoding = serialization.Encoding.PEM, format = serialization.PublicFormat.SubjectPublicKeyInfo)
    msg = ssock.recv(5)
    print(msg)
    a = 0






start()