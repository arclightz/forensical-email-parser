#!/usr/bin/env python
# Author: Saku Pietila
# 11.02.2019

from email.parser import HeaderParser
import sys
import re
from ipwhois import IPWhois
from pprint import pprint
import datetime
from termcolor import colored
import socket
import struct

# Styles for terminal just for the lulz
class style:
   BOLD = '\033[1m'
   END = '\033[0m'

# Regex to parse IP address
ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

# Open file using commanline argument
with open(sys.argv[1], 'r') as mail:
        f = mail.read()
        mail.close()
        
        # Email parser object
        parser = HeaderParser()
        h = parser.parsestr(f)

# Check if the email headers contain SPF header
def find_spf_header():
    sfp_header_value = ""
    sender_ip_address = []

    for k, v in h.items():
        if k == 'received-spf':
            if 'Fail' in v:
                findIP = re.findall(ipPattern,v)
                sender_ip_address = list(set(findIP))
                sfp_header_value = v
            else:
                pass    
        else:
            pass
    print("No sfp header information!")

    if sfp_header_value != "":
        print colored(style.BOLD + '---------- SPF Header Found ---------' + style.END, 'blue')
        print colored(style.BOLD + 'Received-SPF: fail'+ style.END, 'blue')
        print colored(style.BOLD + 'The message should be rejected by the recipient\'s mail exchanger.'+ style.END, 'blue')
        print('Sender address: %s' % " ".join(str(x) for x in sender_ip_address))
        print('Found in : ' + sfp_header_value)


# Parse the sender IP address from SFP header. Need to fix if no SPF header.
def find_spf_header_ip():
    sender_ip_address = []

    for k, v in h.items():
        if k == 'received-spf':
            if 'Fail' in v:
                findIP = re.findall(ipPattern,v)
                sender_ip_address = list(set(findIP))
                return sender_ip_address[0]

# Whois query to check IP information
def ip_whois(ip):
    obj = IPWhois(ip)
    try:
        results = obj.lookup_rdap(depth=1)
    except:
        results = 'notfound'
        print 'ASN Registry Lookup Failed'
    if results != 'notfound':
        print colored(style.BOLD + '\nWhoIS Report for IP: %s' + style.END, 'green') % str(ip)
        print colored(style.BOLD + '--------------- Basic Info ---------------' + style.END, 'blue')
        print 'ASN ID: %s' % results['asn']
        if 'network' in results.keys():
            print 'Org. Name: %s' % results['network']['name']
            print 'CIDR Range: %s' % results['network']['cidr']
            print 'Start Address: %s' % results['network']['start_address']
            print 'Parent Handle: %s' % results['network']['parent_handle']
            print 'Country: %s' % results['network']['country']
        if 'objects' and 'entities' in results.keys():
            print colored(style.BOLD + '\n----------- Per Handle Results -----------' + style.END, 'blue')
            for x in results['entities']:
                print 'Handle: %s' % x
                if 'contact' in results['objects'][x].keys():
                    print '\tKind: %s' % results['objects'][x]['contact']['kind']
                    if results['objects'][x]['contact']['phone'] is not None:
                        for y in results['objects'][x]['contact']['phone']:
                            print '\tPhone: %s' % y['value']
                    if results['objects'][x]['contact']['title'] is not None:
                        print results['objects'][x]['contact']['title']
                    if results['objects'][x]['contact']['role'] is not None:
                        print results['objects'][x]['contact']['role']
                    if results['objects'][x]['contact']['address'] is not None:
                        for y in results['objects'][x]['contact']['address']:
                            print '\tAddress: %s' % y['value'].replace('\n',',')
                    if results['objects'][x]['contact']['email'] is not None:
                        for y in results['objects'][x]['contact']['email']:
                            print '\tEmail: %s' % y['value']

def parse_received():
    received_headers = []
    for k, v in h.items():
        if k == 'Received':
            received_headers.append(str(v))
        else:
                pass
    findIP = re.findall(ipPattern,received_headers[-1])
    sender_ip_address = list(set(findIP))
    
    for ip in sender_ip_address:
        if is_valid_ipv4_address(ip) == True:
            if is_private_ip(ip) == True:
                ip = ""
            else:
                #from IPython import embed; embed()
                print colored(style.BOLD + '\n---------- Sender IP based on Received headers ---------' + style.END, 'blue')
                print('Sender address: %s' % ip)
                print('Found in : ' + received_headers[-1])
                print ip
                return ip
        else:
            return False


def is_valid_ipv4_address(address):
    """Check if the IP is IPv4.
    @param address: IP address to verify.
    @return: boolean representing whether the IP belongs or not to
             a IPv4.
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    """Check if the IP is IPv6.
    @param address: IP address to verify.
    @return: boolean representing whether the IP belongs or not to
             a IPv6.
    """
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True    

def is_private_ip(ip):
    """Check if the IP belongs to private network blocks.
    @param ip: IP address to verify.
    @return: boolean representing whether the IP belongs or not to
             a private network block.
    """
    networks = [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "224.0.0.0/4",
    ]

    for network in networks:
        try:
            ipaddr = struct.unpack(">I", socket.inet_aton(ip))[0]

            netaddr, bits = network.split("/")

            network_low = struct.unpack(">I", socket.inet_aton(netaddr))[0]
            network_high = network_low | 1 << (32 - int(bits)) - 1

            if ipaddr <= network_high and ipaddr >= network_low:
                return True
        except:
            continue

    return False

def main():
    
    print colored(style.BOLD + '\n\n---------- Query started: ' \
                    + str(datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')) \
                    + '---------' + style.END, 'blue')
    find_spf_header()

    if find_spf_header_ip() != None:
        print colored(style.BOLD + '---------- Checking details for SPF IP ---------' + style.END, 'blue')
        ip_whois(find_spf_header_ip())
    else:
        print colored(style.BOLD + '---------- No SPF IP found ---------' + style.END, 'blue')
        parse_received()
        print colored(style.BOLD + '---------- Checking details for Received IP ---------' + style.END, 'blue')
        #from IPython import embed; embed()
        if parse_received() != False:
            if is_private_ip(parse_received()) != False:
                ip_whois(parse_received())
            else:
                print colored(style.BOLD + 'IP adderess of the sender in from private subnet, please check network documentation' + style.END, 'blue')
    
    #parse_received()

    # Python debugger
    #from IPython import embed; embed()

main()

