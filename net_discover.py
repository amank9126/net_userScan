import scapy.all as scapy
import argparse as op


def arguments():
    parser=op.ArgumentParser()
    parser.add_argument("-r","--range",dest="range",help="please give IP or range")
    options=parser.parse_args()
    if not options.range:
        parser.error("please specify range or --help for more info")
    return options


def scan(ip):
    arp_request=scapy.ARP(pdst=ip)
    mac_request=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_mac_request=mac_request/arp_request
    answered=scapy.srp(arp_mac_request,timeout=1,verbose=False)[0]
    return answered

def results(response):
    print("IP\t\t\t\t\tMAC ADDRESS\n-------------------------------------------------------------------")
    if not response:
        print("Not found any network please check command again")
    for i in response:
        print(i[1].psrc + "\t\t" + i[1].hwsrc)
options=arguments()
response=scan(options.range)
results(response)