import sys
from scapy.all import conf, send
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP


def geraConsultas(n_consultas, dest, dom, orig, tipo):
    conf.use_pcap = True

    # Create an IP packet object with source IP as 4.4.4.4 and destination IP as 8.8.8.8
    if orig is not None:
        ip_packet = IP(src=orig, dst=dest)
    else:
        ip_packet = IP(dst=dest)

    # Create a UDP packet object with source port as a random number and destination port as 53 (DNS port)
    udp_packet = UDP(sport=12345, dport=53)

    # Create a DNS packet object with opcode as 0 (query) and rd as 1 (recursion desired)
    dns_packet = DNS(opcode=0, rd=1)

    # Add a DNS query record (DNSQR) to the DNS packet object
    dns_packet = dns_packet / DNSQR(qname=dom, qtype=tipo)

    # Combine the IP, UDP and DNS packets to form the final packet
    final_packet = ip_packet / udp_packet / dns_packet

    # Send the packet using the sr1 method of scapy, which sends the packet and receives the response
    response = send(final_packet, count=n_consultas, return_packets=False)

    # Display the response packet
    print(response)


def getQueryType(tconsulta):
    query_type = ["ANY", "A", "AAAA", "CNAME", "MX", "NS", "PTR", "CERT", "SRV", "TXT", "SOA"]
    return query_type.index(tconsulta)


if __name__ == '__main__':
    if len(sys.argv) == 6:
        dominio = sys.argv[1]
        destino = sys.argv[2]
        origem = sys.argv[3]
        tipo_consulta = getQueryType(sys.argv[4])
        iteracoes = int(sys.argv[5])
        geraConsultas(iteracoes, destino, dominio, origem, tipo_consulta)
    else:
        print("Uso: $ sudo python main.py <domain> <dst_address> <src_address> <tipo_consulta> <iterations>")
