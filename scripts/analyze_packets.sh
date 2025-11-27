




if [ $
    echo "Usage: $0 <pcap_file> [output_dir]"
    echo "Example: $0 ./captures/vmdt_protocol_20240101_120000.pcap"
    exit 1
fi

PCAP_FILE=$1
OUTPUT_DIR=${2:-./analysis}

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file not found: $PCAP_FILE"
    exit 1
fi


mkdir -p "$OUTPUT_DIR"

BASENAME=$(basename "$PCAP_FILE" .pcap)
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo "=========================================="
echo "VMDT Protocol Packet Analysis"
echo "=========================================="
echo "PCAP File: $PCAP_FILE"
echo "Output Dir: $OUTPUT_DIR"
echo "=========================================="
echo ""


echo "1. Basic Statistics:"
echo "-------------------"
tcpdump -r "$PCAP_FILE" -n 2>/dev/null | wc -l | xargs echo "Total packets:"
echo ""


echo "2. Protocol Breakdown:"
echo "---------------------"
echo "TCP packets:"
tcpdump -r "$PCAP_FILE" -n tcp 2>/dev/null | wc -l | xargs echo "  Count:"
echo "UDP packets:"
tcpdump -r "$PCAP_FILE" -n udp 2>/dev/null | wc -l | xargs echo "  Count:"
echo ""


echo "3. Port Statistics:"
echo "------------------"
echo "Top source ports:"
tcpdump -r "$PCAP_FILE" -n 2>/dev/null | awk '{print $3}' | cut -d. -f5 | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
echo ""
echo "Top destination ports:"
tcpdump -r "$PCAP_FILE" -n 2>/dev/null | awk '{print $5}' | cut -d. -f5 | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
echo ""


echo "4. TCP Control Messages (Server Port 8080):"
echo "-------------------------------------------"
tcpdump -r "$PCAP_FILE" -A -n "tcp port 8080" 2>/dev/null > "$OUTPUT_DIR/tcp_control_${BASENAME}.txt"
echo "Saved to: $OUTPUT_DIR/tcp_control_${BASENAME}.txt"
echo ""


echo "5. P2P TCP Messages:"
echo "-------------------"
tcpdump -r "$PCAP_FILE" -A -n "tcp portrange 9000-10000" 2>/dev/null > "$OUTPUT_DIR/p2p_tcp_${BASENAME}.txt"
echo "Saved to: $OUTPUT_DIR/p2p_tcp_${BASENAME}.txt"
echo ""


echo "6. P2P UDP Messages:"
echo "-------------------"
tcpdump -r "$PCAP_FILE" -A -n "udp portrange 9000-10000" 2>/dev/null > "$OUTPUT_DIR/p2p_udp_${BASENAME}.txt"
echo "Saved to: $OUTPUT_DIR/p2p_udp_${BASENAME}.txt"
echo ""


echo "7. VMDT Protocol Markers:"
echo "------------------------"
echo "Searching for VMDT magic strings..."
tcpdump -r "$PCAP_FILE" -A -n 2>/dev/null | grep -i "VMDT\|SHARE_POOL\|MESSAGE_SHARE" > "$OUTPUT_DIR/vmdt_markers_${BASENAME}.txt" || echo "No VMDT markers found"
echo "Saved to: $OUTPUT_DIR/vmdt_markers_${BASENAME}.txt"
echo ""


echo "8. Connection Flow:"
echo "------------------"
tcpdump -r "$PCAP_FILE" -n 2>/dev/null | awk '{print $3, $5}' | sort | uniq > "$OUTPUT_DIR/connections_${BASENAME}.txt"
echo "Saved to: $OUTPUT_DIR/connections_${BASENAME}.txt"
echo ""


echo "9. Packet Size Statistics:"
echo "-------------------------"
tcpdump -r "$PCAP_FILE" -n 2>/dev/null | awk '{print $NF}' | sed 's/len=//' | sort -n | awk '
{
    sum+=$1
    sumsq+=$1*$1
    if(NR==1) min=$1
    max=$1
}
END {
    mean=sum/NR
    variance=(sumsq/NR - mean*mean)
    stddev=sqrt(variance)
    print "  Min:", min, "bytes"
    print "  Max:", max, "bytes"
    print "  Mean:", int(mean), "bytes"
    print "  StdDev:", int(stddev), "bytes"
}'
echo ""


SUMMARY_FILE="$OUTPUT_DIR/summary_${BASENAME}.txt"
{
    echo "VMDT Protocol Analysis Summary"
    echo "Generated: $(date)"
    echo "PCAP File: $PCAP_FILE"
    echo ""
    echo "Total Packets: $(tcpdump -r "$PCAP_FILE" -n 2>/dev/null | wc -l)"
    echo "TCP Packets: $(tcpdump -r "$PCAP_FILE" -n tcp 2>/dev/null | wc -l)"
    echo "UDP Packets: $(tcpdump -r "$PCAP_FILE" -n udp 2>/dev/null | wc -l)"
    echo ""
    echo "Files Generated:"
    echo "  - tcp_control_${BASENAME}.txt"
    echo "  - p2p_tcp_${BASENAME}.txt"
    echo "  - p2p_udp_${BASENAME}.txt"
    echo "  - vmdt_markers_${BASENAME}.txt"
    echo "  - connections_${BASENAME}.txt"
} > "$SUMMARY_FILE"

echo "Analysis complete!"
echo "Summary saved to: $SUMMARY_FILE"
echo "All analysis files saved to: $OUTPUT_DIR"

