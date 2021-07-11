import socket
import ssl


IP = '127.0.0.1'
PORT = 1251

CERT = 'ca_cert.crt'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((IP, PORT))
s.listen()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

context.load_cert_chain(certfile=CERT, keyfile='ca_key.key')

ssock = context.wrap_socket(s, server_side=True)
while True:
    try:
        conn, addr = ssock.accept()
        print(f"clinet {addr} connected!")
        conn.send(bytes('hello', 'utf-8'))
    except:
        print(f"something got fucked")
        continue
