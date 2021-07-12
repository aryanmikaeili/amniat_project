import socket
import ssl
import threading

from cryptography import x509
from cryptography.x509.oid import  NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from datetime import datetime, timedelta
import OpenSSL.crypto
import random


IP = '127.0.0.1'
PORT = 2500

CERT = 'ca_cert.pem'
KEY = 'ca_key.key'

HEADERSIZE = 64




with open('ca_cert.pem') as crt_file:
    CA_cert = crt_file.read()
    CA_cert = OpenSSL.crypto.load_certificate( OpenSSL.crypto.FILETYPE_PEM, CA_cert)
    CA_cert = x509.load_pem_x509_certificate(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, CA_cert), default_backend())


with open('ca_key.key') as key:
    CA_private_key = key.read()
    CA_private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, CA_private_key)
    CA_private_key = serialization.load_pem_private_key(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, CA_private_key), password=None, backend=default_backend())

def verify_cert(cert):
    v = cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    if v is None:
        return True
    return False
def make_cert(der_cert):
    self_signed_cert = x509.load_der_x509_certificate(der_cert, default_backend())
    if not verify_cert(self_signed_cert):
        return -1
    now = datetime.utcnow()
    basic_cons = x509.BasicConstraints(ca=False, path_length=None)

    cert = (
        x509.CertificateBuilder()
            .subject_name(self_signed_cert.subject)
            .issuer_name(CA_cert.issuer)
            .public_key(self_signed_cert.public_key())
            .serial_number(random.randint(1000, 10000))
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(basic_cons, True)
            .sign(CA_private_key, hashes.SHA256(), default_backend())
    )
    return cert

def send_message(socket, msg):
    message_len = f"{len(msg):<{HEADERSIZE}}"
    message_len = bytes(message_len, 'utf-8')
    socket.send(message_len)
    socket.send(msg)


def handle_client(conn, addr):
    connected = True
    while connected:
        message_len = conn.recv(HEADERSIZE).decode('utf-8')
        message_len = int(message_len)
        msg = conn.recv(message_len)
        cert = make_cert(msg)
        if cert == -1:
            send_message(conn, bytes('something went wrong', 'utf-8'))
            continue
        cert = cert.public_bytes(serialization.Encoding.DER)
        send_message(conn, cert)
        connected = False
    print(f"{addr}: {msg}")
    return msg



if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((IP, PORT))
    s.listen()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    context.load_cert_chain(certfile=CERT, keyfile=KEY)

    ssock = context.wrap_socket(s, server_side=True)

    while True:
        try:
            conn, addr = ssock.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
            print(f"clinet {addr} connected!")

        except:
            print(f"something got fucked")
            continue
