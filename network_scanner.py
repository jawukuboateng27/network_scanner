#!/usr/bin/env python
import scapy.all as scapy
import optparse

def scan(ip):
    # ARP request asking for IP address
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    Clients_list = []
    for element in answered_list:
        client_dict = {"Ip": element[1].psrc, "MAC Address": element[1].hwsrc}
        Clients_list.append(client_dict)
        return Clients_list


def get_target():
    parser = optparse.OptionParser()
    parser.add_option("-t", dest="ip")
    (options,arguments) = parser.parse_args()
    return options

def print_result(result_list):
    print("IP\t\t\tMAC Address\n------------------------------------------")
    for client in result_list:
        print(client["Ip"]+"\t\t" + client["MAC Address"])

options = get_target()
# scan_result = scan("192.168.92.2/24")
scan_result = scan(options.ip)
print_result(scan_result)