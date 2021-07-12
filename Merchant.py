import socket
import ssl
import time


class Merchant:
    def __init__(self):
        self.items = {'condom': 1000, 'sex toy': 2000}
        self.back_account = None
        self.sll_sock = None

    def add_item(self, commodity, price):
        self.items[commodity] = price

    def set_up_server(self, ip, port, cert, key):

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port))
        s.listen(5)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        context.load_cert_chain(certfile=cert, keyfile=key)

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
    CERT = 'ca_cert.crt'
    KEY = 'ca_key.key'

    merchant = Merchant()
    merchant.set_up_server(IP, PORT, CERT, KEY)
    merchant.run_server()

