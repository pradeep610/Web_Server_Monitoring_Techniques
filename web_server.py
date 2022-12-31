from scapy.utils import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest
import nmap
import os
import psutil


def request_application(file_name):
    ser_app = '10.5.25.171:63927'
    request=0
    (server_ip, server_port) = ser_app.split(':')
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        ether_pkt = Ether(pkt_data)
        if ether_pkt.type != 0x0800:
            # disregard non-IPv4 packets
            continue

        ip_pkt = ether_pkt[IP]
        
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue
        
        tcp_pkt = ip_pkt[TCP]
        # print('{}'.format(tcp_pkt.dport))
        if(ip_pkt.dst==server_ip and tcp_pkt.dport == int(server_port)):
            request+=1
    print("\nthe number of request to a particular application on a web server is : {}".format(request))


def established(conn):
    print("established connections are:")
    established_connections = os.system(conn)
    print(established_connections)
def half_open(half):
    half_open_connections = os.system(half)
    print("\nthe half open connections are: {}".format(half_open_connections))
def port_scanner():
    # take the range of ports to  be scanned
    begin = 75
    end = 80
  
    # assign the target ip to be scanned to a variable
    target = '192.168.100.138'
   
    # instantiate a PortScanner object
    scanner = nmap.PortScanner()

    print("\n\nPort status of the web server are:\n")
    print("\nhere we are scanning for ports from 75 - 80 on the server\n")
    for i in range(begin,end+1):
   
        # scan the target port
        res = scanner.scan(target,str(i))
   
        # the result is a dictionary containing several information we only need to check if the port is opened or closed
        # so we will access only that information in the dictionary
        res = res['scan'][target]['tcp'][i]['state']
   
        print(f'port {i} is {res}.')

def server_bandwidth(bandwidth):
    print("the server bandwidth is : ")
    result=psutil.net_io_counters(pernic=True)
    print("")
    print(f"{'Interface':<30}{'Bytes received':^20}{'Bytes sent':>10}")
    print("")
    for interface in result:
        print(f'{interface:<30}{str(result[interface].bytes_recv):^20}{str(result[interface].bytes_sent):^10}')
    print("\nThe above data is being used by below applications\n ")
    ser_bandwidth = os.system(bandwidth)
    print(ser_bandwidth)


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))

    client_ip = '10.5.25.171'
    server = '216.92.49.183:80'

    (server_ip, server_port) = server.split(':')
    
    count = 0
    interesting_packet_count = 0
    syn = 0
    res = 0
    get=0
    counter = 0
    
    
    for (pkt_data, pkt_metadata,) in RawPcapReader(file_name):
        count += 1
        
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            # LLC frames will have 'len' instead of 'type'.
            # We disregard those
            continue
        if ether_pkt.type!=0x0800:
            # disregard non-IPv4 packets
            continue
        ip_pkt = ether_pkt[IP]
        ip_pkt_http = ether_pkt[IP]
        ip_pkt_reset = ether_pkt[IP]  
        
        if ip_pkt.proto != 6:
            # Ignore non-TCP packet
            continue

        # if (ip_pkt.src != server_ip) and (ip_pkt.src != client_ip):
        #     # Uninteresting source IP address
        #     continue
        if((ip_pkt_reset.src != server_ip) and(ip_pkt_reset.dst!=server_ip)):
            # here we are ignoring all the packets whose source or destination IP address is not server IP address
            continue
        tcp_pkt_reset = ip_pkt_reset[TCP]
        if 'R' in str(tcp_pkt_reset.flags):
            # counting the number of reset flags
            res+=1
        # the below variable counts the number of packets that are useful to us from the entire pcap capture file
        interesting_packet_count += 1

        if (ip_pkt.dst != server_ip):
            # Uninteresting destination IP address
            continue

        tcp_pkt = ip_pkt[TCP]
        if 'S' in str(tcp_pkt.flags):
            syn+=1

        if tcp_pkt.haslayer(HTTPRequest):
            method = tcp_pkt[HTTPRequest].Method.decode()
            if method == 'GET':
                get+=1

    print('{} contains {} packets ({} interesting)'.
          format(file_name, count, interesting_packet_count))
    print('\nNumber of syn connections = {}'.format(syn))
    print('\nNumber of res connections = {}\n'.format(res))

    established('sudo netstat -atupen | grep ESTABLISHED')

    half_open('sudo netstat -a | grep ^SYN')

    request_application('http website.pcap')

    print('\nNumber of get requests to the server = {}\n'.format(get))

    server_bandwidth('sudo netstat -at')

    port_scanner()


process_pcap('http website.pcap')

