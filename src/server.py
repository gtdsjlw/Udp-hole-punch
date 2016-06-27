"""
sadf
"""
import sys
import socket
import logging
import threading
import struct
import binascii

STAGE_INIT = 0
STAGE_QUERY = 1
STAGE_REQEUST_CONNECT = 2
STAGE_HOLE_PUNCH = 3
STAGE_HOLE_PUNCHED = 4

def to_bytes(s):
    if bytes != str:
        if type(s) == str:
            return s.encode('utf-8')
    return s

def to_str(s):
    if bytes != str:
        if type(s) == bytes:
            return s.decode('utf-8')
    return s

class Data:

    def __init__(self, data, stage):
        # self.magic = 0xdeadbeef
        try:
            self.magic = stage
            self.crc = binascii.crc32(data)
            self.len = len(data)
            self.data = data
        except binascii.Error as err:
            logging.error(err)
            sys.exit(-1)

    def to_bytes(self):
        data = struct.pack("III", self.magic, self.crc, self.len) + self.data
        return data



class UdpServer(object):

    ADDRESS_PORT = ("0.0.0.0", 33362)

    def __init__(self, address=None):
        # self.address = address
        if not address:
            self.address = UdpServer.ADDRESS_PORT
        else:
            self.address = address
        logging.info("udp server listen addr " + self.address[0] + ":" + str(self.address[1]))
        # self.ip_list = []
        self.client = {}
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(self.address)
            self.sock.setblocking(False)
            self.sock.settimeout(500)
            logging.info("udp server listen ")
        except OSError as err:
            logging.error(err)
            sys.exit(err.errno)
        except Exception as e:
            logging.error(e)
            sys.exit(-1)

    def talk(self, client_sock, data):
        try:
            logging.info("Talk thread start")
            if len(data) < 12:
                logging.error("data length less than 12")
                return
            # parse uid/ip/port
            stage, crc32, length = struct.unpack('III', data[:12])
            msg = data[12:length + 12]
            if stage == STAGE_INIT:   # first connection
                uid, ip, port = struct.unpack("I4sI", msg[:12])
                ip_address = socket.inet_ntoa(ip)
                logging.info("client conn id: " + str(uid) + ", internel address : " + ip_address + \
                    ":" + str(port))
                if uid not in self.client:
                    client = {}
                    client["local_ip"] = ip_address
                    client["local_port"] = port
                    client["ip"] = client_sock[0]
                    client["port"] = client_sock[1]
                    self.client[uid] = client
                client_ip = socket.inet_aton(client_sock[0])
                data = struct.pack("I4sI", uid, client_ip, client_sock[1])
                data = Data(data, STAGE_INIT).to_bytes()
                count = self.sock.sendto(data, client_sock)
                logging.info("send " + str(count) + " bytes")
                pass
            elif stage == STAGE_QUERY:   # query other client
                client_uid, remote_uid = struct.unpack("II", msg[:8])
                if client_uid not in self.client:
                    logging.warning("query failed : need connect server first!")
                elif remote_uid not in self.client:
                    logging.warning("query failed : no such client!")
                else:
                    remote_ip = socket.inet_aton(self.client[remote_uid]["ip"])
                    remote_port = self.client[remote_uid]["port"]
                    data = struct.pack("I4sI", remote_uid, remote_ip, remote_port)
                    data = Data(data, STAGE_QUERY).to_bytes()
                    self.sock.sendto(data, client_sock)
                    pass
            elif stage == STAGE_REQEUST_CONNECT:
                # check crc32

                client_uid, remote_uid = struct.unpack('II', msg[:8])
                # check existence of client_uid and remote_uid
                if client_uid not in self.client:
                    logging.warning("connect failed : client id {} not in the list".format(client_uid))
                elif remote_uid not in self.client:
                    logging.warning("connect failed : remote id {} not in the list".format(remote_uid))
                else:
                    # key + ip + port
                    client = self.client[client_uid]
                    data = struct.pack('I4sI', client_uid, socket.inet_aton(client["ip"]), client["port"])
                    data = Data(data, STAGE_HOLE_PUNCH).to_bytes()
                    remote_client = self.client[remote_uid]
                    remote_sock = (remote_client["ip"], remote_client["port"])
                    count = self.sock.sendto(data, remote_sock)
                    logging.info("hole punching send {} bytes if success {} - {}:{} can talk to {} - {}:{}".format(count, \
                        client_uid, client["ip"], client["port"], remote_uid, remote_client["ip"], remote_client["port"]))
            elif stage == STAGE_HOLE_PUNCHED:
                # check crc32
                client_uid, remote_uid, remote_ip, remote_port = struct.unpack('II4sI', msg[:4])
                data = struct.pack('I4sI', remote_uid, remote_ip, remote_port) + b'hole punched'
                    
        except socket.error as err:
            logging.error(err)
            sys.exit(err.errno)

    def start(self):
        logging.info("udp server start ...")
        while True:
            data, client = self.sock.recvfrom(1024)
            if not data:
                logging.info("recv no data from " + client[0] + ":" + str(client[1]))
                break
            logging.info("recv data from " + client[0] + ":" + str(client[1]))
            # logging.debug("data : " + bytes.decode(data))
            # threading.Thread(target=self.talk, args=(client, data)).start()
            self.talk(client, data)


def Test():
    UdpServer().start()

if __name__ == "__main__":
    logging.basicConfig(level=5,
                        format='%(asctime)s %(levelname)-8s %(lineno)03d %(message)s ',
                        datefmt='%Y-%m-%d %H:%M:%S')
    # data = struct.pack('I', 74)
    # print(bytes.decode(data))
    # data = struct.unpack('I', data)
    # print(data)
    # print(type(data))
    Test()
