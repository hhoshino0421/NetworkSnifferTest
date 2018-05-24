from scapy.all import *


# パケット処理用コールバック関数
def packet_callback(packet):
    print(packet.show())


# スニッファーを起動
sniff(prn=packet_callback, count=1)