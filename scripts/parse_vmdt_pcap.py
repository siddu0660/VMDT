import sys
import argparse
from collections import defaultdict
from datetime import datetime
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from scapy.layers.inet import IP
import base64
import re
import csv
SERVER_PORT = 8080
P2P_PORT_MIN = 9000
P2P_PORT_MAX = 10000
MESSAGE_TYPES = {'CREATE_CLUSTER': 'CREATE_CLUSTER', 'JOIN_CLUSTER': 'JOIN_CLUSTER', 'LIST_CLUSTERS': 'LIST_CLUSTERS', 'LEAVE_CLUSTER': 'LEAVE_CLUSTER', 'GET_CLUSTER_MEMBERS': 'GET_CLUSTER_MEMBERS', 'REGISTER_P2P_PORT': 'REGISTER_P2P_PORT', 'GET_CLIENT_INFO': 'GET_CLIENT_INFO', 'CLIENT_INFO': 'CLIENT_INFO', 'CLUSTER_CREATED': 'CLUSTER_CREATED', 'CLUSTER_JOINED': 'CLUSTER_JOINED', 'CLUSTER_LIST': 'CLUSTER_LIST', 'CLUSTER_READY': 'CLUSTER_READY', 'MESSAGE_SHARE': 'MESSAGE_SHARE', 'SHARE_POOL_ADD': 'SHARE_POOL_ADD', 'SHARE_POOL_CLAIM': 'SHARE_POOL_CLAIM', 'SHARE_POOL_ACK': 'SHARE_POOL_ACK', 'SHARE_POOL_UNFREEZE': 'SHARE_POOL_UNFREEZE', 'SHARE_POOL_REMOVE': 'SHARE_POOL_REMOVE', 'OK': 'OK', 'ERROR': 'ERROR'}

class VMDTParser:

    def __init__(self, verbose=False, server_port=8080):
        self.verbose = verbose
        self.server_port = server_port
        self.stats = {'total_packets': 0, 'tcp_server': 0, 'tcp_p2p': 0, 'udp_p2p': 0, 'messages': defaultdict(int), 'connections': set(), 'clients': set(), 'clusters': set()}
        self.packets = []

    def parse_tcp_control_message(self, packet, src_port, dst_port):
        if Raw not in packet:
            return None
        payload = packet[Raw].load
        try:
            message = payload.decode('utf-8', errors='ignore').strip()
        except:
            return None
        if not message:
            return None
        msg_type = None
        for msg_key in MESSAGE_TYPES:
            if message.startswith(msg_key + '|') or message == msg_key:
                msg_type = msg_key
                break
        if not msg_type:
            parts = message.split('|')
            if parts:
                msg_type = parts[0]
        return {'type': 'TCP_CONTROL', 'src_port': src_port, 'dst_port': dst_port, 'message_type': msg_type, 'raw_message': message, 'timestamp': packet.time, 'src_ip': packet[IP].src if IP in packet else 'unknown', 'dst_ip': packet[IP].dst if IP in packet else 'unknown'}

    def parse_udp_data_packet(self, packet):
        if Raw not in packet:
            return None
        payload = packet[Raw].load
        if len(payload) < 64:
            return None
        try:
            vmdt_header = payload[:64].decode('ascii', errors='ignore')
        except:
            return None
        magic = vmdt_header[:4] if len(vmdt_header) >= 4 else ''
        if magic != 'VMDT':
            return None
        version = vmdt_header[4:7].strip('\x00') if len(vmdt_header) >= 7 else ''
        source_id = vmdt_header[8:24].strip('\x00') if len(vmdt_header) >= 24 else ''
        dest_id = vmdt_header[24:40].strip('\x00') if len(vmdt_header) >= 40 else ''
        message_id = vmdt_header[40:56].strip('\x00') if len(vmdt_header) >= 56 else ''
        share_index = vmdt_header[56:60].strip('\x00') if len(vmdt_header) >= 60 else ''
        rdt_header = None
        payload_data = None
        if len(payload) >= 80:
            rdt_data = payload[64:80]
            if len(rdt_data) == 16:
                seq_num = int.from_bytes(rdt_data[0:2], byteorder='big')
                ack_num = int.from_bytes(rdt_data[2:4], byteorder='big')
                packet_type = rdt_data[4]
                flags = rdt_data[5]
                window_size = int.from_bytes(rdt_data[6:8], byteorder='big')
                checksum = int.from_bytes(rdt_data[8:10], byteorder='big')
                payload_len = int.from_bytes(rdt_data[10:12], byteorder='big')
                rdt_header = {'seq_num': seq_num, 'ack_num': ack_num, 'packet_type': packet_type, 'flags': flags, 'window_size': window_size, 'checksum': checksum, 'payload_len': payload_len}
                if len(payload) > 80:
                    payload_data = payload[80:]
        return {'type': 'UDP_DATA', 'src_port': packet[UDP].sport, 'dst_port': packet[UDP].dport, 'vmdt_header': {'magic': magic, 'version': version, 'source_id': source_id, 'dest_id': dest_id, 'message_id': message_id, 'share_index': share_index}, 'rdt_header': rdt_header, 'payload_size': len(payload_data) if payload_data else 0, 'timestamp': packet.time, 'src_ip': packet[IP].src if IP in packet else 'unknown', 'dst_ip': packet[IP].dst if IP in packet else 'unknown'}

    def parse_packet(self, packet):
        self.stats['total_packets'] += 1
        if IP not in packet:
            return None
        parsed = None
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            if src_port == self.server_port or dst_port == self.server_port:
                self.stats['tcp_server'] += 1
                parsed = self.parse_tcp_control_message(packet, src_port, dst_port)
                if parsed:
                    self.stats['connections'].add((packet[IP].src, src_port, packet[IP].dst, dst_port))
            elif P2P_PORT_MIN <= src_port <= P2P_PORT_MAX or P2P_PORT_MIN <= dst_port <= P2P_PORT_MAX:
                self.stats['tcp_p2p'] += 1
                parsed = self.parse_tcp_control_message(packet, src_port, dst_port)
                if parsed:
                    self.stats['connections'].add((packet[IP].src, src_port, packet[IP].dst, dst_port))
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if P2P_PORT_MIN <= src_port <= P2P_PORT_MAX or P2P_PORT_MIN <= dst_port <= P2P_PORT_MAX:
                self.stats['udp_p2p'] += 1
                parsed = self.parse_udp_data_packet(packet)
                if parsed:
                    self.stats['connections'].add((packet[IP].src, src_port, packet[IP].dst, dst_port))
        if parsed:
            self.packets.append(parsed)
            if parsed.get('message_type'):
                self.stats['messages'][parsed['message_type']] += 1
            if 'raw_message' in parsed:
                msg = parsed['raw_message']
                client_ids = re.findall('client_\\d+', msg)
                self.stats['clients'].update(client_ids)
                cluster_ids = re.findall('cluster_\\w+', msg)
                self.stats['clusters'].update(cluster_ids)
        return parsed

    def print_statistics(self):
        print('\n' + '=' * 70)
        print('VMDT Protocol Statistics')
        print('=' * 70)
        print(f"Total Packets:        {self.stats['total_packets']}")
        print(f"TCP Server ({self.server_port}):    {self.stats['tcp_server']}")
        print(f"TCP P2P (9000-10000): {self.stats['tcp_p2p']}")
        print(f"UDP P2P (9000-10000): {self.stats['udp_p2p']}")
        print(f"Unique Connections:   {len(self.stats['connections'])}")
        print(f"Unique Clients:       {len(self.stats['clients'])}")
        print(f"Unique Clusters:      {len(self.stats['clusters'])}")
        print('\nMessage Types:')
        for msg_type, count in sorted(self.stats['messages'].items()):
            print(f'  {msg_type:25s}: {count}')
        print('=' * 70)

    def print_packets(self, filter_type=None, limit=None):
        print('\n' + '=' * 70)
        print('Parsed Packets')
        print('=' * 70)
        count = 0
        for pkt in self.packets:
            if filter_type and pkt.get('type') != filter_type:
                continue
            if limit and count >= limit:
                print(f'\n... (showing first {limit} packets)')
                break
            count += 1
            ts = float(pkt['timestamp'])
            timestamp = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            print(f'\n[{count}] {timestamp}')
            print(f"  Type: {pkt['type']}")
            print(f"  Source: {pkt['src_ip']}:{pkt['src_port']}")
            print(f"  Dest:   {pkt['dst_ip']}:{pkt['dst_port']}")
            if pkt['type'] == 'TCP_CONTROL':
                print(f"  Message Type: {pkt.get('message_type', 'UNKNOWN')}")
                msg = pkt.get('raw_message', '')
                if len(msg) > 100:
                    print(f'  Message: {msg[:100]}...')
                else:
                    print(f'  Message: {msg}')
            elif pkt['type'] == 'UDP_DATA':
                vmdt = pkt.get('vmdt_header', {})
                print(f'  VMDT Header:')
                print(f"    Magic:      {vmdt.get('magic', 'N/A')}")
                print(f"    Version:    {vmdt.get('version', 'N/A')}")
                print(f"    Source ID:  {vmdt.get('source_id', 'N/A')}")
                print(f"    Dest ID:    {vmdt.get('dest_id', 'N/A')}")
                print(f"    Message ID: {vmdt.get('message_id', 'N/A')}")
                print(f"    Share Index: {vmdt.get('share_index', 'N/A')}")
                rdt = pkt.get('rdt_header')
                if rdt:
                    print(f'  RDT Header:')
                    print(f"    Seq Num:    {rdt.get('seq_num', 'N/A')}")
                    print(f"    Ack Num:    {rdt.get('ack_num', 'N/A')}")
                    print(f"    Packet Type: 0x{rdt.get('packet_type', 0):02x}")
                    print(f"    Flags:      0x{rdt.get('flags', 0):02x}")
                    print(f"    Window:     {rdt.get('window_size', 'N/A')}")
                    print(f"    Payload Len: {pkt.get('payload_size', 0)} bytes")

    def export_messages(self, output_file, message_type=None):
        with open(output_file, 'w') as f:
            f.write('VMDT Protocol Messages Export\n')
            f.write('=' * 70 + '\n\n')
            for pkt in self.packets:
                if pkt['type'] == 'TCP_CONTROL':
                    if message_type and pkt.get('message_type') != message_type:
                        continue
                    ts = float(pkt['timestamp'])
                    timestamp = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    f.write(f"[{timestamp}] {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}\n")
                    f.write(f"Type: {pkt.get('message_type', 'UNKNOWN')}\n")
                    f.write(f"Message: {pkt.get('raw_message', '')}\n")
                    f.write('-' * 70 + '\n\n')

    def export_to_csv(self, output_file, filter_type=None):
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['timestamp', 'packet_type', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'message_type', 'raw_message', 'vmdt_magic', 'vmdt_version', 'vmdt_source_id', 'vmdt_dest_id', 'vmdt_message_id', 'vmdt_share_index', 'rdt_seq_num', 'rdt_ack_num', 'rdt_packet_type', 'rdt_flags', 'rdt_window_size', 'rdt_payload_len', 'payload_size']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for pkt in self.packets:
                if filter_type and pkt.get('type') != filter_type:
                    continue
                ts = float(pkt['timestamp'])
                timestamp = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                row = {'timestamp': timestamp, 'packet_type': pkt.get('type', ''), 'src_ip': pkt.get('src_ip', ''), 'src_port': pkt.get('src_port', ''), 'dst_ip': pkt.get('dst_ip', ''), 'dst_port': pkt.get('dst_port', ''), 'message_type': pkt.get('message_type', ''), 'raw_message': pkt.get('raw_message', ''), 'vmdt_magic': '', 'vmdt_version': '', 'vmdt_source_id': '', 'vmdt_dest_id': '', 'vmdt_message_id': '', 'vmdt_share_index': '', 'rdt_seq_num': '', 'rdt_ack_num': '', 'rdt_packet_type': '', 'rdt_flags': '', 'rdt_window_size': '', 'rdt_payload_len': '', 'payload_size': ''}
                if pkt.get('type') == 'UDP_DATA':
                    vmdt = pkt.get('vmdt_header', {})
                    row['vmdt_magic'] = vmdt.get('magic', '')
                    row['vmdt_version'] = vmdt.get('version', '')
                    row['vmdt_source_id'] = vmdt.get('source_id', '')
                    row['vmdt_dest_id'] = vmdt.get('dest_id', '')
                    row['vmdt_message_id'] = vmdt.get('message_id', '')
                    row['vmdt_share_index'] = vmdt.get('share_index', '')
                    rdt = pkt.get('rdt_header')
                    if rdt:
                        row['rdt_seq_num'] = rdt.get('seq_num', '')
                        row['rdt_ack_num'] = rdt.get('ack_num', '')
                        row['rdt_packet_type'] = f"0x{rdt.get('packet_type', 0):02x}"
                        row['rdt_flags'] = f"0x{rdt.get('flags', 0):02x}"
                        row['rdt_window_size'] = rdt.get('window_size', '')
                        row['rdt_payload_len'] = rdt.get('payload_len', '')
                    row['payload_size'] = pkt.get('payload_size', 0)
                writer.writerow(row)

    def find_share_pool_messages(self):
        print('\n' + '=' * 70)
        print('Share Pool Messages')
        print('=' * 70)
        share_pool_packets = [p for p in self.packets if p.get('message_type') and 'SHARE_POOL' in p.get('message_type')]
        for pkt in share_pool_packets:
            ts = float(pkt['timestamp'])
            timestamp = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            print(f"\n[{timestamp}] {pkt['message_type']}")
            print(f"  {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
            msg = pkt.get('raw_message', '')
            parts = msg.split('|')
            if len(parts) > 0:
                print(f"  Message ID: {(parts[1] if len(parts) > 1 else 'N/A')}")
                if len(parts) > 2:
                    print(f"  Sender: {(parts[2] if len(parts) > 2 else 'N/A')}")
                if len(parts) > 3:
                    print(f"  Receiver: {(parts[3] if len(parts) > 3 else 'N/A')}")
                if len(parts) > 4:
                    print(f"  Total Shares: {(parts[4] if len(parts) > 4 else 'N/A')}")
                if len(parts) > 5:
                    print(f"  Active Shares: {(parts[5] if len(parts) > 5 else 'N/A')}")

    def find_cluster_operations(self):
        print('\n' + '=' * 70)
        print('Cluster Operations')
        print('=' * 70)
        cluster_ops = ['CREATE_CLUSTER', 'JOIN_CLUSTER', 'LEAVE_CLUSTER', 'LIST_CLUSTERS', 'CLUSTER_CREATED', 'CLUSTER_JOINED', 'CLUSTER_READY', 'GET_CLUSTER_MEMBERS']
        cluster_packets = [p for p in self.packets if p.get('message_type') in cluster_ops]
        for pkt in cluster_packets:
            ts = float(pkt['timestamp'])
            timestamp = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            print(f"\n[{timestamp}] {pkt['message_type']}")
            print(f"  {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
            msg = pkt.get('raw_message', '')
            if len(msg) > 150:
                print(f'  {msg[:150]}...')
            else:
                print(f'  {msg}')

def main():
    parser = argparse.ArgumentParser(description='Parse VMDT protocol pcap files')
    parser.add_argument('pcap_file', help='Path to pcap file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-s', '--stats', action='store_true', help='Show statistics only')
    parser.add_argument('-p', '--packets', type=int, help='Limit number of packets to display')
    parser.add_argument('-f', '--filter', choices=['TCP_CONTROL', 'UDP_DATA'], help='Filter by packet type')
    parser.add_argument('-m', '--messages', action='store_true', help='Show share pool messages')
    parser.add_argument('-c', '--clusters', action='store_true', help='Show cluster operations')
    parser.add_argument('-e', '--export', help='Export messages to text file')
    parser.add_argument('--csv', help='Export packets to CSV file')
    parser.add_argument('--message-type', help='Filter by specific message type')
    parser.add_argument('--server-port', type=int, default=8080, help='Server port number (default: 8080)')
    args = parser.parse_args()
    print(f'Loading pcap file: {args.pcap_file}')
    try:
        packets = rdpcap(args.pcap_file)
        print(f'Loaded {len(packets)} packets')
    except Exception as e:
        print(f'Error loading pcap file: {e}')
        return 1
    vmdt_parser = VMDTParser(verbose=args.verbose, server_port=args.server_port)
    print('Parsing packets...')
    for packet in packets:
        vmdt_parser.parse_packet(packet)
    print(f'Parsed {len(vmdt_parser.packets)} VMDT protocol packets')
    if args.stats:
        vmdt_parser.print_statistics()
    elif args.messages:
        vmdt_parser.find_share_pool_messages()
    elif args.clusters:
        vmdt_parser.find_cluster_operations()
    else:
        vmdt_parser.print_statistics()
        vmdt_parser.print_packets(filter_type=args.filter, limit=args.packets)
    if args.export:
        vmdt_parser.export_messages(args.export, args.message_type)
        print(f'\nMessages exported to: {args.export}')
    if args.csv:
        vmdt_parser.export_to_csv(args.csv, filter_type=args.filter)
        print(f'\nPackets exported to CSV: {args.csv}')
    return 0
if __name__ == '__main__':
    sys.exit(main())