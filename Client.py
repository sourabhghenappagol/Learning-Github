import socket
from DiffieHellman import DiffieHellman
import json


class ClientSocket:
    def __init__(self, debugflag):
        self.__dh = DiffieHellman.DH()
        self.__debugflag = debugflag

    #def init_commit(self,socket):


    def initDiffieHellman(self, socket):

        socket.send("connected".encode())

        s = socket.recv(1024)

        if self.__debugflag:
            print(s)

        jsonData1 = json.loads(s.decode())
        jsonData1 = jsonData1["Initialization"]

        self.__dh.p = int(jsonData1["p"])
        self.__dh.g = int(jsonData1["Generator"])
        self.__dh.h = int(jsonData1['h'])

        pr = self.__dh.p
        gen = self.__dh.g
        keyc = self.__dh.h

        x= self.__dh.x
        r= self.__dh.r

        self.__dh.c = ((gen **  x) * (keyc ** r)) % pr

        step2 = "{"
        step2+= "\"Exchange\":"
        step2 += "{"
        step2 += "\"step\": {},".format(2)
        step2 += "\"x\": {},".format(x)
        step2 += "\"r\": {},".format(r)
        step2 += "\"Commitment\": {}".format(self.__dh.c)
        step2 += "}}"
        socket.send(step2.encode())


        step1 = socket.recv(1024)

        if self.__debugflag:
            print(step1)

        # Step 1.1: Parse them
        jsonData2 = json.loads(step1.decode())
        jsonData2 = jsonData2["dh-keyexchange"]

        self.__dh.base = int(jsonData2["base"])
        self.__dh.sharedPrime = int(jsonData2["prime"])
        publicSecret = int(jsonData2["publicSecret"])

        # Step2: calculate public secret and send to server
        calcedPubSecret = str(self.__dh.calcPublicSecret())
        step2 = "{"
        step2 += "\"dh-keyexchange\":"
        step2 += "{"
        step2 += "\"step\": {},".format(2)
        step2 += "\"publicSecret\": {}".format(calcedPubSecret)
        step2 += "}}"
        socket.send(step2.encode())

        # Step3: calculate the shared secret
        self.__dh.calcSharedSecret(publicSecret)

    def start_client(self, ip):
        # Start the Socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((ip, 50000));

            # Start the Key
            #self.init_commit(sock)
            self.initDiffieHellman(sock)
            print("Shared Key is {}".format(self.__dh.key))

        finally:
            # Close the Socket
            sock.close()
