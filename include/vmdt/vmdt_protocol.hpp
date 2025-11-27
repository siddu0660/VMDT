#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <arpa/inet.h>
#include <stdexcept>

namespace vmdt {
namespace p2p {
namespace protocol {

constexpr const char* VMDT_VERSION = "1.0";
constexpr const char* VMDT_MAGIC = "VMDT";


enum class RDTType : uint8_t {
    DATA = 0x01,        
    ACK = 0x02,         
    NAK = 0x03,         
    SYN = 0x04,         
    FIN = 0x05,         
    HEARTBEAT = 0x06    
};


enum class RDTFlags : uint8_t {
    NONE = 0x00,
    FINAL = 0x01,       
    RETRANSMIT = 0x02,  
    CHECKSUM = 0x04     
};

struct VMDTHeader {
    char magic[4];           
    char version[4];         
    char source_id[16];      
    char dest_id[16];        
    char message_id[16];     
    char share_index[4];     
    char reserved[4];        
    
    VMDTHeader() {
        memset(this, 0, sizeof(VMDTHeader));
        memcpy(magic, VMDT_MAGIC, 4);
        memcpy(version, VMDT_VERSION, 3);
    }
    
    std::string to_string() const {
        std::ostringstream oss;
        oss << "VMDT[" 
            << "magic=" << std::string(magic, 4) << ","
            << "ver=" << std::string(version, 4) << ","
            << "src=" << std::string(source_id, strnlen(source_id, 16)) << ","
            << "dst=" << std::string(dest_id, strnlen(dest_id, 16)) << ","
            << "msg=" << std::string(message_id, strnlen(message_id, 16)) << ","
            << "idx=" << std::string(share_index, strnlen(share_index, 4)) << "]";
        return oss.str();
    }
};

struct RDTHeader {
    uint16_t seq_num;        
    uint16_t ack_num;        
    uint8_t packet_type;     
    uint8_t flags;           
    uint16_t window_size;    
    uint16_t checksum;       
    uint16_t payload_len;    
    uint8_t reserved[4];     
    
    RDTHeader() {
        memset(this, 0, sizeof(RDTHeader));
    }
    
    std::string to_string() const {
        std::ostringstream oss;
        oss << "RDT["
            << "seq=" << ntohs(seq_num) << ","
            << "ack=" << ntohs(ack_num) << ","
            << "type=" << static_cast<int>(packet_type) << ","
            << "flags=0x" << std::hex << static_cast<int>(flags) << std::dec << ","
            << "win=" << ntohs(window_size) << ","
            << "len=" << ntohs(payload_len) << "]";
        return oss.str();
    }
};


struct UDPPacket {
    VMDTHeader vmdt_header;
    RDTHeader rdt_header;
    std::vector<uint8_t> payload;
    
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> buffer;
        buffer.resize(sizeof(VMDTHeader) + sizeof(RDTHeader) + payload.size());
        
        memcpy(buffer.data(), &vmdt_header, sizeof(VMDTHeader));
        memcpy(buffer.data() + sizeof(VMDTHeader), &rdt_header, sizeof(RDTHeader));
        memcpy(buffer.data() + sizeof(VMDTHeader) + sizeof(RDTHeader), 
               payload.data(), payload.size());
        
        return buffer;
    }
    
    
    static UDPPacket deserialize(const uint8_t* data, size_t len) {
        UDPPacket packet;
        
        if (len < sizeof(VMDTHeader) + sizeof(RDTHeader)) {
            throw std::runtime_error("Packet too short");
        }
        
        memcpy(&packet.vmdt_header, data, sizeof(VMDTHeader));
        memcpy(&packet.rdt_header, data + sizeof(VMDTHeader), sizeof(RDTHeader));
        
        size_t payload_len = ntohs(packet.rdt_header.payload_len);
        if (len < sizeof(VMDTHeader) + sizeof(RDTHeader) + payload_len) {
            throw std::runtime_error("Payload length mismatch");
        }
        
        packet.payload.assign(data + sizeof(VMDTHeader) + sizeof(RDTHeader),
                             data + sizeof(VMDTHeader) + sizeof(RDTHeader) + payload_len);
        
        return packet;
    }
    
    std::string to_string() const {
        std::ostringstream oss;
        oss << vmdt_header.to_string() << " " << rdt_header.to_string();
        return oss.str();
    }
};

class TCPMessage {
public:
    static std::string format(const std::string& msg_type, const std::vector<std::string>& params) {
        std::ostringstream oss;
        oss << VMDT_MAGIC << "/TCP/" << VMDT_VERSION << "/" << msg_type;
        for (const auto& param : params) {
            oss << "/" << param;
        }
        oss << "\n";
        return oss.str();
    }
    
    static bool parse(const std::string& message, std::string& msg_type, std::vector<std::string>& params) {
        std::istringstream iss(message);
        std::string token;
        std::vector<std::string> parts;
        
        while (std::getline(iss, token, '/')) {
            parts.push_back(token);
        }
        
        
        if (!parts.empty() && !parts.back().empty() && parts.back().back() == '\n') {
            parts.back().pop_back();
        }
        
        
        if (parts.size() < 4 || parts[0] != VMDT_MAGIC || parts[1] != "TCP") {
            return false;
        }
        
        msg_type = parts[3];
        params.clear();
        for (size_t i = 4; i < parts.size(); ++i) {
            params.push_back(parts[i]);
        }
        
        return true;
    }
};


inline UDPPacket create_data_packet(
    const std::string& source_id,
    const std::string& dest_id,
    const std::string& message_id,
    int share_index,
    uint16_t seq_num,
    const std::vector<uint8_t>& payload) {
    
    UDPPacket packet;
    
    
    strncpy(packet.vmdt_header.source_id, source_id.c_str(), 15);
    strncpy(packet.vmdt_header.dest_id, dest_id.c_str(), 15);
    strncpy(packet.vmdt_header.message_id, message_id.c_str(), 15);
    snprintf(packet.vmdt_header.share_index, 4, "%04d", share_index);
    
    
    packet.rdt_header.seq_num = htons(seq_num);
    packet.rdt_header.ack_num = 0;
    packet.rdt_header.packet_type = static_cast<uint8_t>(RDTType::DATA);
    packet.rdt_header.flags = 0;
    packet.rdt_header.window_size = htons(1024);
    packet.rdt_header.checksum = 0;
    packet.rdt_header.payload_len = htons(static_cast<uint16_t>(payload.size()));
    
    packet.payload = payload;
    
    return packet;
}

inline UDPPacket create_ack_packet(uint16_t ack_num) {
    UDPPacket packet;
    packet.rdt_header.ack_num = htons(ack_num);
    packet.rdt_header.packet_type = static_cast<uint8_t>(RDTType::ACK);
    packet.rdt_header.payload_len = 0;
    return packet;
}


inline uint16_t calculate_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i += 2) {
        if (i + 1 < len) {
            sum += (data[i] << 8) | data[i + 1];
        } else {
            sum += data[i] << 8;
        }
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

} 
} 
} 

