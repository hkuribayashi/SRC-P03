from scapy.all import conf, send
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP

conf.use_pcap = True

# Create an IP packet object with source IP as 4.4.4.4 and destination IP as 8.8.8.8
ip_packet = IP(src="4.4.4.4", dst="8.8.8.8")

# Create a UDP packet object with source port as a random number and destination port as 53 (DNS port)
udp_packet = UDP(sport=12345, dport=53)

# Create a DNS packet object with opcode as 0 (query) and rd as 1 (recursion desired)
dns_packet = DNS(opcode=0, rd=1)

# Add a DNS query record (DNSQR) to the DNS packet object
dns_packet = dns_packet / DNSQR(qname="www.example.com")

# Combine the IP, UDP and DNS packets to form the final packet
final_packet = ip_packet / udp_packet / dns_packet

# Send the packet using the sr1 method of scapy, which sends the packet and receives the response
response = send(final_packet, count=5, return_packets=False)

# Display the response packet
print(response)