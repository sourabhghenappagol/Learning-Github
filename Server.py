import socketserver
from DiffieHellman import DiffieHellman
from KryptoMath import Prime
import json


class ServerSocket(socketserver.BaseRequestHandler):

    def initDiffieHellman(self):
        if self.request.recv(1024).decode() != "connected":
            print("Error while connecting")

        self.__dh.g = int(self.__dh.calcGenerator())
        generator = self.__dh.g
        self.__dh.h = self.__dh.calckey()
        calkey = self.__dh.h
        pr= self.__dh.p
        step0 = "{"
        step0 += "\"Initialization\":"
        step0 += "{"
        step0 += "\"step\": {},".format(1)
        step0 += "\"p\": {},".format(self.__dh.p)
        step0 += "\"h\": {},".format(self.__dh.h)
        step0 += "\"Generator\": {}".format(self.__dh.g)
        step0 += "}}"
        self.request.send(step0.encode())

        step3 = self.request.recv(1024)

        if self.__debugflag:
            print(step3)

        # step 2.1 Parse them
        jsonData1 = json.loads(step3.decode())
        jsonData1 = jsonData1["Exchange"]

        Receiver_commit = int(jsonData1["Commitment"])
        x_rec = int(jsonData1["x"])
        r_rec = int(jsonData1["r"])

        commit_value = ((generator ** x_rec) * (calkey ** r_rec)) % pr

        if Receiver_commit == commit_value:
            print("Authenticated")


        publicSecret = self.__dh.calcPublicSecret()

        # Step1: share primes and public secret
        step1 = "{"
        step1 += "\"dh-keyexchange\":"
        step1 += "{"
        step1 += "\"step\": {},".format(1)
        step1 += "\"base\": {},".format(self.__dh.base)
        step1 += "\"prime\": {},".format(self.__dh.sharedPrime)
        step1 += "\"publicSecret\": {}".format(publicSecret)
        step1 += "}}"
        self.request.send(step1.encode())

        # step2: receive the public secret from client
        step2 = self.request.recv(1024)

        if self.__debugflag:
            print(step2)

        # step 2.1 Parse them
        jsonData = json.loads(step2.decode())
        jsonData = jsonData["dh-keyexchange"]

        publicSecret = int(jsonData["publicSecret"])

        # step3: calculate the shared secret
        self.__dh.calcSharedSecret(publicSecret)

    # Client connected
    def handle(self):
        self.__debugflag = self.server.conn
        self.__dh = DiffieHellman.DH()

        # print the Client-IP
        print("[{}] Client connected.".format(self.client_address[0]))

        # init
        # self.initCommitment()
        self.initDiffieHellman()
        print("> The shared key is {}".format(self.__dh.key))

def start_server(debugflag):
    # start the server and serve forever
    server = socketserver.ThreadingTCPServer(("", 50000), ServerSocket)

    # pass the debug-flag to the SocketServer-Class
    server.conn = debugflag

    # And serve
    server.serve_forever()
