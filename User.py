import socket
import ssl
import time


class User:
    def __init__(self):
        self.bought_items = {'nothing': 0}
        self.bank_account = None
        self.bitcoin_account = None
        # should be moved to bank account later!
        self.balance = 1000000
        self.sll_sock = None

    def connect_to_merchant(self, ip, port, merchant_crt):

        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(merchant_crt)
        sock = socket.create_connection((ip, port))
        self.sll_sock = context.wrap_socket(sock, server_hostname='CA_SERVER')
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
    CERT = 'ca_cert.crt'

    user = User()
    user.connect_to_merchant(IP, PORT, CERT)
    user.start_communicate_merchant()
