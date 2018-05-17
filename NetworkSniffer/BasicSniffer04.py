# ライブラリインポート
import socket
import os
import struct
from ctypes import *

import threading
import time
from netaddr import IPNetwork, IPAddress

import traceback

# 定数定義
# リスンするホストのIP
#host = "172.24.231.174"
host = "192.168.100.143"

# 標的のサブネット
subnet = "192.168.100.0/24"

# ICMPレスポンスのチェック用マジック文字列定義
magic_message = "PYTHONRULES!"

# IPヘッダ
class IP(Structure):
    _fields_ = [
        ("ihl",             c_uint8,     4),
        ("version",         c_uint8,     4),
        ("tos",             c_uint8),
        ("len",             c_uint16),
        ("id",              c_uint16),
        ("offset",          c_uint16),
        ("ttl",             c_uint8),
        ("protocol_num",    c_uint8),
        ("sum",             c_uint16),
        ("src",             c_uint32),
        ("dst",             c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):

        # プロトコルの定数値を名称にマッピング
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        # 可読なIPアドレスの値に変換
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # 可読なプロトコル名称に変換
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

# ICMPヘッダ
class ICMP(Structure):

    _fields_ = [
        ("type",            c_uint8),
        ("code",            c_uint8),
        ("checksum",        c_uint16),
        ("unused",          c_uint16),
        ("next_hop_mtu",    c_uint16)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass


# UDPデータグラムをサブネット全体に送信
def udp_sender(subnet, magic_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):

        try:
            sender.sendto(magic_message.encode('utf-8'), ("%s" % ip, 65212))

            # デバッグ用
            # print("Send ip: %s" % (ip,))

        except:

            print(traceback.format_exc())


if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


# パケットの送信開始
t = threading.Thread(target=udp_sender, args=(subnet,magic_message))
t.start()

try:

    while True:

        # パケットの読み込み
        raw_buffer = sniffer.recvfrom(65565)[0]

        # バッファの最初の20バイトからIP構造体を作成
        ip_header = IP(raw_buffer[0:20])

        # 検出されたプロトコルとホストを出力
        # print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

        # ICMPであればそれを処理
        if ip_header.protocol == "ICMP":
            # ICMPパケットの位置を計算
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]

            # ICMP構造体を作成
            icmp_header = ICMP(buf)

            # デバッグ用
            # print("code: %s type: %s" % (icmp_header.code, icmp_header.type))

            if icmp_header.code == 3 and icmp_header.type == 3:

                # デバッグ用
                # print("Address: %s" % ip_header.src_address)

                if IPAddress(ip_header.src_address) in IPNetwork(subnet):

                    # デバッグ用
                    # print("len(raw_buffer): %d" % len(raw_buffer))
                    # print("len(magic_message): %d" % len(magic_message))
                    # print("buffer string: %s" % raw_buffer[len(raw_buffer) - len(magic_message):] )

                    if (raw_buffer[len(raw_buffer) - len(magic_message):]).decode('utf-8') == magic_message:

                        print("Host up: %s" % ip_header.src_address)

except KeyboardInterrupt:

    # Widnowsの場合はプロミスキャストモードを無効化
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

