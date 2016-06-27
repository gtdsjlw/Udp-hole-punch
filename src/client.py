import sys
import struct
import socket
import logging
import binascii
import uuid
import threading

STAGE_INIT = 0
STAGE_QUERY = 1
STAGE_REQEUST_CONNECT = 2
STAGE_HOLE_PUNCH = 3


class Data:

    def __init__(self, data, stage):
        # self.magic = 0xdeadbeef
        try:
            self.magic = stage
            if data:
                self.crc = binascii.crc32(data)
                self.len = len(data)
                self.data = data
            else:
                self.len = 0
                self.crc = 0
                self.data = None
        except binascii.Error as err:
            logging.error(err)
            sys.exit(-1)

    def to_bytes(self):
        data = struct.pack("III", self.magic, self.crc, self.len)
        if self.data:
            data = data + self.data
        return data

class UdpClient:
    SERVER_ADDR = ("188.166.241.157", 33362)
    SERVER2_ADDR = ("104.131.47.197", 33363)
    # SERVER_ADDR = ("127.0.0.1", 33362)
    def __init__(self, id):
        self.remote_client = {}
        self.alive = True
        try:
            # self.uid = binascii.crc32(uuid.uuid1().bytes)
            self.uid = int(id)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # self.sock.bind(("0.0.0.0", 7788))
            self.sock.setblocking(False)
            self.sock.settimeout(500)
            # self.sock.bind(("0.0.0.0", 7676))
            # self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.__get_local_ip()
            logging.info("client id: " + str(self.uid) + " addr : " + self.internel_addr[0] + ":" + \
                str(self.internel_addr[1]))
        except socket.error as err:
            logging.error(err)
            sys.exit(err.errno)

    def __get_local_ip(self):
        try:
            # self.sock.connect(('8.8.8.8', 0))
            # self.internel_addr = self.sock.getsockname()
            ip = socket.gethostbyname(socket.gethostname())
            self.sock.sendto(b"socket", ('8.8.8.8', 0))
            port = self.sock.getsockname()
            self.internel_addr = (ip, port[1])
            logging.info("client internel address : " + self.internel_addr[0] + ":" + str(self.internel_addr[1]))
            pass
        except socket.error as err:
            logging.error(err)
            sys.exit(err.errno)

    def stage_init(self):
        try:
            ip = socket.inet_aton(self.internel_addr[0])
            data = struct.pack('I4sI', self.uid, ip, self.internel_addr[1])
            data = Data(data, STAGE_INIT).to_bytes()
            self.sock.sendto(data, UdpClient.SERVER_ADDR)
            data, server_addr = self.sock.recvfrom(4096)
            stage, crc32, length = struct.unpack('III', data[:12])
            if stage == STAGE_INIT:
                # check crc32
                uid, client_ip, client_port = struct.unpack('I4sI', data[12:length + 12])
                self.externel_ip = socket.inet_ntoa(client_ip)
                self.externel_port = client_port
                logging.info("client net address " + self.externel_ip + ":" + str(self.externel_port))
            else:
                logging.info("init error")
                sys.exit(-1)
        except struct.error as err:
            logging.error(err.msg)
            sys.exit(-1)
        except socket.error as err:
            logging.error(err)
            sys.exit(err.errno)

    def stage_query(self, remote_id):
        self.remote_id = remote_id
        try:
            data = struct.pack("II", self.uid, remote_id)
            # data = struct.pack("II", self.uid, self.uid)
            data = Data(data, STAGE_QUERY).to_bytes()
            self.sock.sendto(data, UdpClient.SERVER_ADDR)

            data, server_addr = self.sock.recvfrom(1024)
            stage, crc32, length = struct.unpack('III', data[:12])
            data = data[12:12+length]
            if stage == STAGE_QUERY:
                remote_uid, remote_ip, remote_port = struct.unpack("I4sI", data)
                if remote_uid != remote_id:
                    logging.error("query remote client error, query " + str(remote_id) + " but get " + str(remote_uid))
                    sys.exit()
                remote_client = (socket.inet_ntoa(remote_ip), remote_port)
                # remote_client["ip"] = socket.inet_ntoa(remote_ip)
                # remote_client["port"] = remote_port
                self.remote_client[remote_uid] = remote_client
                # logging.info("remote client - " + remote_client["ip"] + ":" + str(remote_client["port"]))
                logging.info("remote client - " + remote_client[0] + ":" + str(remote_client[1]))
            else:
                logging.error("query remote client error")
        except struct.error as err:
            logging.error(err.msg)
            sys.exit(-1)
        except socket.error as err:
            logging.error(err)
            sys.exit(err.errno)

    def stage_connect(self):
        if not self.remote_id:
            logging.error("connect error : no remote key")
            sys.exit()
        elif self.remote_id not in self.remote_client:
            logging.error("connect error : no such remote client - " + self.remote_id)
            sys.exit()
        else:
            remote_client = self.remote_client[self.remote_id]
            # first connect to the server
            data = struct.pack('II', self.uid, self.remote_id)
            data = Data(data, STAGE_REQEUST_CONNECT).to_bytes()
            count = self.sock.sendto(data, UdpClient.SERVER_ADDR)
            logging.info("stage connect : request connection to {}:{}".format(remote_client[0], remote_client[1]))
            data, addr = self.sock.recvfrom(4096)
            stage, crc32, length = struct.unpack('III', data[:12])
            if stage == STAGE_REQEUST_CONNECT:
                # check crc32

                data = data[12:12+length]
                if length < 2 or data[:2] != b'OK'
                    logging.error("request connection failed")
                    sys.exit()
                logging.info("request connection success")
                    
                # send msg to remote client
                data = struct.pack('I', self.uid) + b'Hello'
                data = Data(data, STAGE_REQEUST_CONNECT).to_bytes()
                count = self.sock.sendto(data, remote_client)
                logging.info("connect to {}:{}, send {} bytes data".format(remote_client[0], remote_client[1], count))
                data, addr = self.sock.recvfrom(4096)
                stage, crc32, length = struct.unpack('III', data[:12])
                if stage == STAGE_REQEUST_CONNECT:
                    # check crc32
                    data = data[12:12+length]
                    remote_id = struct.unpack('I', data[:4])
                    if remote_id == self.remote_id:
                        logging.info("connect success, remote key : " + str(remote_id))
                    else:
                        logging.error("stage connect error")
                        sys.exit()
            else:
                logging.error("stage connect error")
                sys.exit()

    def send_thread(self):
        while self.alive:
            try:
                data = str.encode(input(""))
                count = self.sock.sendto(data, (self.remote_client[self.remote_id]))
                logging.info("send count {}".format(count))
            except socket.error as err:
                logging.error(err)
                sys.exit()
            except KeyboardInterrupt:
                logging.warning("closing threds")
                sys.exit()

    def read_thread(self):
        while self.alive:
            try:
                data, addr = self.sock.recvfrom(4096)
                logging.info("recv data from {}:{} - ".format(addr[0], addr[1]) + bytes.decode(data)) 
            except socket.error as err:
                logging.error(err)
                sys.exit()
            except KeyboardInterrupt:
                logging.warning("closing threds")
                sys.exit()


    def talkto(self, remote_id):
        self.stage_init()
        self.stage_query(remote_id)
        self.stage_connect()
        read_thread = threading.Thread(target=self.read_thread)
        send_thread = threading.Thread(target=self.send_thread)

        read_thread.start()
        send_thread.start()

        read_thread.join()
        send_thread.join()
        
if __name__ == "__main__":
    logging.basicConfig(level=5,
                        format='%(asctime)s %(levelname)-8s %(lineno)03d %(message)s ',
                        datefmt='%Y-%m-%d %H:%M:%S')
    client = UdpClient(1111)
    # client.stage_init()
    # client.stage_query(123423)

    client.talkto(2222)
