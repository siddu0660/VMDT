





SERVER_PORT=${1:-8080}           
P2P_PORT_MIN=${2:-9000}          
P2P_PORT_MAX=${3:-10000}         
OUTPUT_DIR=${4:-./captures}      
INTERFACE=${5:-any}              


mkdir -p "$OUTPUT_DIR"


TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PCAP_FILE="$OUTPUT_DIR/vmdt_protocol_${TIMESTAMP}.pcap"

echo "=========================================="
echo "VMDT Protocol Packet Capture"
echo "=========================================="
echo "Server Port:     $SERVER_PORT"
echo "P2P Port Range:  $P2P_PORT_MIN-$P2P_PORT_MAX"
echo "Interface:       $INTERFACE"
echo "Output File:     $PCAP_FILE"
echo "=========================================="
echo ""
echo "Starting capture... (Press Ctrl+C to stop)"
echo ""






FILTER="(tcp port $SERVER_PORT) or (tcp portrange $P2P_PORT_MIN-$P2P_PORT_MAX) or (udp portrange $P2P_PORT_MIN-$P2P_PORT_MAX)"


sudo tcpdump -i "$INTERFACE" \
    -w "$PCAP_FILE" \
    -s 0 \
    -n \
    -v \
    "$FILTER" \
    2>&1 | tee "$OUTPUT_DIR/capture_${TIMESTAMP}.log"

echo ""
echo "Capture complete!"
echo "PCAP file saved to: $PCAP_FILE"
echo "Log file saved to: $OUTPUT_DIR/capture_${TIMESTAMP}.log"

