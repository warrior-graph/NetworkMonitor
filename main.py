from pyshark import LiveCapture
from collections import defaultdict
from prettytable import PrettyTable

flow_dict = defaultdict(lambda: 0)
src_addr_dict = defaultdict(lambda: 0)
dst_addr_dict = defaultdict(lambda: 0)
n = 1000
def sniff():
    cap = LiveCapture(interface='enp7s0')
    total_pkts = 0
    amount_of_data = 0

    for pkt in cap.sniff_continuously(packet_count=n):
        try:
            protocol = str(pkt.transport_layer)
            src_addr = str(pkt.ip.src)
            dst_addr = str(pkt.ip.dst)
            src_port = str(pkt[pkt.transport_layer].srcport)
            dst_port = str(pkt[pkt.transport_layer].dstport)
            payload_length = int(pkt.data.len)
            
            flow = (src_addr, src_port, dst_addr, dst_port)

            flow_dict[flow] += payload_length
            
            src_addr_dict[src_addr] += 1
            dst_addr_dict[dst_addr] += 1

        except AttributeError:
            pass


def main():
    sniff()
    table = PrettyTable(['src_addr', 'src_port', 'dst_addr', 'dst_port', 'amount of data'])
    data = list(flow_dict.keys())

    for d in data:
        table.add_row(list(d) + [flow_dict[d]])
    print(table)

    pkt_lenght_average = sum(flow_dict.values()) / n
    print('Average of packet length:', int(pkt_lenght_average))
    print('IP most accessed: ', max(src_addr_dict, key=src_addr_dict.get))
    print('IP that most transmitted: ', max(dst_addr_dict, key=dst_addr_dict.get))

if __name__ == '__main__':
    main()