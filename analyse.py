#!/usr/bin/env python

from email.parser import HeaderParser
import sys
import re
from ipwhois import IPWhois
from pprint import pprint
import datetime
from termcolor import colored

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


def main():
    
    print colored(style.BOLD + '\n\n---------- Query started: ' \
                    + str(datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')) \
                    + '---------' + style.END, 'blue')
    find_spf_header()
    #from IPython import embed; embed()

    if find_spf_header_ip() != None:
        ip_whois(find_spf_header_ip())
    else:
        pass

    # Python debugger
    #from IPython import embed; embed()

main()

