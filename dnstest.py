# Imports
from scapy.all import *
from pprint import pprint
import operator

# Parameters
interface = "eth0"  # Interface you want to use
dns_source = "local-ip"  # IP of that interface
dns_destination = ["ip1", "ip2", "ip3"]  # List of DNS Server IPs

time_to_live = 128  # IP TTL
query_name = "google.com"  # DNS Query Name
query_type = ["ANY", "A", "AAAA", "CNAME", "MX", "NS", "PTR", "CERT", "SRV", "TXT", "SOA"]  # DNS Query Types

# Initialise variables
results = []
packet_number = 0

# Loop through all query types then all DNS servers
for i in range(0, len(query_type)):
    for j in range(0, len(dns_destination)):
        packet_number += 1

        # Craft the DNS query packet with scapy
        packet = IP(src=dns_source, dst=dns_destination[j], ttl=time_to_live) / UDP() / DNS(rd=1,
                                                                                            qd=DNSQR(qname=query_name,
                                                                                                     qtype=query_type[
                                                                                                         i]))

        # Sending the packet
        try:
            query = sr1(packet, iface=interface, verbose=False, timeout=8)
            print("Packet #{} sent!".format(packet_number))
        except:
            print("Error sending packet #{}".format(packet_number))

        # Creating dictionary with received information
        try:
            result_dict = {
                'dns_destination': dns_destination[j],
                'query_type': query_type[i],
                'query_size': len(packet),
                'response_size': len(query),
                'amplification_factor': (len(query) / len(packet)),
                'packet_number': packet_number
            }
            results.append(result_dict)
        except:
            pass

# Sort dictionary by the amplification factor
results.sort(key=operator.itemgetter('amplification_factor'), reverse=True)

# Print results
pprint(results)