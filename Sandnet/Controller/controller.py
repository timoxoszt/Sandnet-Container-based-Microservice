import socket,sys
from struct import *
import json

def eth_addr(packet):
    mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (packet[0], packet[1], packet[2], packet[3], packet[4], packet[5])
    return mac

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    while True:
        # receive a packet
        packet = s.recvfrom(65565)
        packet = packet[0]

        # parse ethernet header
        eth_length = 14
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])

        # Parse IP packets
        ip_header = packet[0:20]
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        # TCP protocol
        tcp_header = packet[iph_length:iph_length + 20]
        tcph = unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4

        result = {
            "Destination MAC": eth_addr(packet[0:6]),
            "Source MAC": eth_addr(packet[6:12]),
            "Version": version,
            "IP Header Length": ihl,
            "TTL": ttl,
            "Protocol": protocol,
            "Source Address": s_addr,
            "Destination Address": d_addr,
            "Source Port": source_port,
            "Destination Port": dest_port,
            "Sequence Number": sequence,
            "Acknowledgement": acknowledgement,
            "TCP header length": tcph_length,
        }
        print(json.dumps(result))

main()