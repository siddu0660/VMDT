import csv
import sys
import re
from collections import defaultdict

def populate_tcp_fields(csv_file):
    connections = {}
    rows = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            src_ip = row['src_ip']
            src_port = int(row['src_port'])
            dst_ip = row['dst_ip']
            dst_port = int(row['dst_port'])
            raw_message = row.get('raw_message', '')
            if src_port < dst_port or (src_port == dst_port and src_ip < dst_ip):
                conn_key = (src_ip, src_port, dst_ip, dst_port)
                is_forward = True
            else:
                conn_key = (dst_ip, dst_port, src_ip, src_port)
                is_forward = False
            if conn_key not in connections:
                base_seq = 1000 + abs(hash(conn_key)) % 50000
                connections[conn_key] = {'forward_seq': base_seq, 'reverse_seq': base_seq + 1000, 'forward_ack': 0, 'reverse_ack': 0}
            conn = connections[conn_key]
            payload_size = len(raw_message.encode('utf-8')) if raw_message else 0
            message_type = row.get('message_type', '')
            flags = 24
            if is_forward:
                seq_num = conn['forward_seq']
                ack_num = conn['forward_ack'] if conn['forward_ack'] > 0 else 0
                conn['forward_seq'] += max(payload_size, 1)
            else:
                seq_num = conn['reverse_seq']
                ack_num = conn['reverse_ack'] if conn['reverse_ack'] > 0 else conn['forward_seq']
                conn['reverse_ack'] = conn['forward_seq']
                conn['reverse_seq'] += max(payload_size, 1)
                conn['forward_ack'] = conn['reverse_seq']
            window_size = 65535
            vmdt_magic = ''
            vmdt_version = ''
            vmdt_source_id = ''
            vmdt_dest_id = ''
            vmdt_message_id = ''
            vmdt_share_index = ''
            if raw_message:
                parts = raw_message.split('|')
                if message_type and message_type in ['SHARE_POOL_ADD', 'SHARE_POOL_CLAIM', 'SHARE_POOL_ACK', 'SHARE_POOL_REMOVE', 'MESSAGE_SHARE']:
                    vmdt_magic = 'VMDT'
                    vmdt_version = '1.0'
                    if len(parts) >= 2:
                        vmdt_message_id = parts[1] if parts[1] else ''
                    if message_type == 'SHARE_POOL_ADD' and len(parts) >= 4:
                        vmdt_source_id = parts[2] if parts[2] else ''
                        vmdt_dest_id = parts[3] if parts[3] else ''
                    elif message_type == 'SHARE_POOL_CLAIM' and len(parts) >= 4:
                        vmdt_source_id = parts[2] if parts[2] else ''
                        vmdt_share_index = parts[3] if parts[3] else ''
                        if vmdt_message_id and '_' in vmdt_message_id:
                            msg_parts = vmdt_message_id.split('_')
                            if len(msg_parts) >= 2:
                                vmdt_dest_id = f'client_{msg_parts[1]}' if len(msg_parts) > 1 else ''
                    elif message_type == 'SHARE_POOL_ACK' and len(parts) >= 3:
                        vmdt_source_id = parts[2] if parts[2] else ''
                        if vmdt_message_id and '_' in vmdt_message_id:
                            msg_parts = vmdt_message_id.split('_')
                            if len(msg_parts) >= 2:
                                vmdt_dest_id = f'client_{msg_parts[1]}' if len(msg_parts) > 1 else ''
                    elif message_type == 'SHARE_POOL_REMOVE' and len(parts) >= 2:
                        if vmdt_message_id and '_' in vmdt_message_id:
                            msg_parts = vmdt_message_id.split('_')
                            if len(msg_parts) >= 2:
                                vmdt_dest_id = f'client_{msg_parts[1]}' if len(msg_parts) > 1 else ''
                            if len(msg_parts) >= 4:
                                vmdt_source_id = f'client_{msg_parts[3]}' if len(msg_parts) > 3 else ''
                elif message_type:
                    client_ids = re.findall('client_\\d+', raw_message)
                    if len(client_ids) >= 1:
                        vmdt_source_id = client_ids[0]
                    if len(client_ids) >= 2:
                        vmdt_dest_id = client_ids[1]
                    elif len(client_ids) == 1:
                        if 'GET_CLIENT_INFO' in message_type and len(parts) >= 3:
                            vmdt_source_id = parts[1] if parts[1] else ''
                            vmdt_dest_id = parts[2] if parts[2] else ''
                    if any((keyword in message_type for keyword in ['CLUSTER', 'SHARE', 'MESSAGE'])):
                        vmdt_magic = 'VMDT'
                        vmdt_version = '1.0'
            row['rdt_seq_num'] = str(seq_num)
            row['rdt_ack_num'] = str(ack_num)
            row['rdt_packet_type'] = f'0x{flags:02x}'
            row['rdt_flags'] = f'0x{flags:02x}'
            row['rdt_window_size'] = str(window_size)
            row['rdt_payload_len'] = str(payload_size)
            row['payload_size'] = str(payload_size)
            row['vmdt_magic'] = vmdt_magic
            row['vmdt_version'] = vmdt_version
            row['vmdt_source_id'] = vmdt_source_id
            row['vmdt_dest_id'] = vmdt_dest_id
            row['vmdt_message_id'] = vmdt_message_id
            row['vmdt_share_index'] = vmdt_share_index
            rows.append(row)
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['timestamp', 'packet_type', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'message_type', 'raw_message', 'vmdt_magic', 'vmdt_version', 'vmdt_source_id', 'vmdt_dest_id', 'vmdt_message_id', 'vmdt_share_index', 'rdt_seq_num', 'rdt_ack_num', 'rdt_packet_type', 'rdt_flags', 'rdt_window_size', 'rdt_payload_len', 'payload_size']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    print(f'Populated {len(rows)} rows with TCP header information')
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python populate_packet_fields.py <csv_file>')
        sys.exit(1)
    populate_tcp_fields(sys.argv[1])