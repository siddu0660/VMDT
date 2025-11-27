




OUTPUT_FILE=${1:-vmdt_capture_$(date +%Y%m%d_%H%M%S).pcap}
SERVER_PORT=8080
P2P_MIN=9000
P2P_MAX=10000

echo "Capturing VMDT protocol traffic..."
echo "Output: $OUTPUT_FILE"
echo "Ports: Server=$SERVER_PORT, P2P=$P2P_MIN-$P2P_MAX"
echo "Press Ctrl+C to stop"
echo ""

sudo tcpdump -i any -w "$OUTPUT_FILE" -s 0 -n -v \
    "(tcp port $SERVER_PORT) or (tcp portrange $P2P_MIN-$P2P_MAX) or (udp portrange $P2P_MIN-$P2P_MAX)"

echo ""
echo "Capture saved to: $OUTPUT_FILE"

