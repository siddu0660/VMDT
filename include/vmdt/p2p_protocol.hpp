#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <sstream>

namespace vmdt {
namespace p2p {
namespace protocol {


enum class MessageType {
    CREATE_CLUSTER,
    JOIN_CLUSTER,
    LIST_CLUSTERS,
    CLUSTER_CREATED,
    CLUSTER_JOINED,
    CLUSTER_LIST,
    ERROR,
    CLUSTER_READY,
    LEAVE_CLUSTER,
    SEND_MESSAGE,
    MESSAGE_SHARE,
    MESSAGE_RECEIVED,
    GET_CLUSTER_MEMBERS,
    CLUSTER_MEMBERS,
    REGISTER_P2P_PORT,
    GET_CLIENT_INFO,
    CLIENT_INFO,
    SHARE_POOL_ADD,
    SHARE_POOL_CLAIM,
    SHARE_POOL_ACK,
    SHARE_POOL_UNFREEZE,
    SHARE_POOL_REMOVE
};


class Message {
public:
    static std::string create_cluster(const std::string& client_id, int n, int k) {
        return "CREATE_CLUSTER|" + client_id + "|" + std::to_string(n) + "|" + std::to_string(k);
    }
    
    static std::string join_cluster(const std::string& client_id, const std::string& cluster_id) {
        return "JOIN_CLUSTER|" + client_id + "|" + cluster_id;
    }
    
    static std::string list_clusters(const std::string& client_id) {
        return "LIST_CLUSTERS|" + client_id;
    }
    
    static std::string leave_cluster(const std::string& client_id) {
        return "LEAVE_CLUSTER|" + client_id;
    }
    
    static std::string send_message(const std::string& client_id, const std::string& target_client_id, const std::string& message) {
        
        return "SEND_MESSAGE|" + client_id + "|" + target_client_id + "|" + message;
    }
    
    static std::string message_share(const std::string& from_client_id, const std::string& to_client_id, 
                                     const std::string& target_client_id, int share_index, const std::string& share_data) {
        return "MESSAGE_SHARE|" + from_client_id + "|" + to_client_id + "|" + target_client_id + "|" 
               + std::to_string(share_index) + "|" + share_data;
    }
    
    static std::string get_cluster_members(const std::string& client_id) {
        return "GET_CLUSTER_MEMBERS|" + client_id;
    }
    
    static std::string cluster_members(const std::vector<std::string>& members) {
        std::string result = "CLUSTER_MEMBERS";
        for (const auto& member : members) {
            result += "|" + member;
        }
        return result;
    }
    
    static std::string register_p2p_port(const std::string& client_id, uint16_t p2p_port) {
        return "REGISTER_P2P_PORT|" + client_id + "|" + std::to_string(p2p_port);
    }
    
    static std::string get_client_info(const std::string& client_id, const std::string& target_client_id) {
        return "GET_CLIENT_INFO|" + client_id + "|" + target_client_id;
    }
    
    static std::string client_info(const std::string& ip, uint16_t port) {
        return "CLIENT_INFO|" + ip + "|" + std::to_string(port);
    }
    
    
    static std::string share_pool_add(const std::string& message_id, const std::string& sender_id,
                                     const std::string& receiver_id, int total_shares, int active_shares,
                                     const std::vector<std::pair<int, std::string>>& shares,
                                     bool is_file = false, const std::string& filename = "") {
        std::string result = "SHARE_POOL_ADD|" + message_id + "|" + sender_id + "|" + receiver_id + "|"
                           + std::to_string(total_shares) + "|" + std::to_string(active_shares) + "|"
                           + (is_file ? "FILE" : "TEXT") + "|" + filename;
        for (const auto& [index, share_data] : shares) {
            result += "|" + std::to_string(index) + ":" + share_data;
        }
        return result;
    }
    
    static std::string share_pool_claim(const std::string& message_id, const std::string& claimer_id, int share_index) {
        return "SHARE_POOL_CLAIM|" + message_id + "|" + claimer_id + "|" + std::to_string(share_index);
    }
    
    static std::string share_pool_ack(const std::string& message_id, const std::string& receiver_id) {
        return "SHARE_POOL_ACK|" + message_id + "|" + receiver_id;
    }
    
    static std::string share_pool_unfreeze(const std::string& message_id, int share_index) {
        return "SHARE_POOL_UNFREEZE|" + message_id + "|" + std::to_string(share_index);
    }
    
    static std::string share_pool_remove(const std::string& message_id) {
        return "SHARE_POOL_REMOVE|" + message_id;
    }
    
    static MessageType parse_type(const std::string& message) {
        if (message.empty()) {
            return MessageType::ERROR;
        }
        
        size_t pos = message.find('|');
        std::string type_str = (pos == std::string::npos) ? message : message.substr(0, pos);
        
        
        type_str.erase(0, type_str.find_first_not_of(" \t\n\r"));
        type_str.erase(type_str.find_last_not_of(" \t\n\r") + 1);
        
        if (type_str == "CREATE_CLUSTER") return MessageType::CREATE_CLUSTER;
        if (type_str == "JOIN_CLUSTER") return MessageType::JOIN_CLUSTER;
        if (type_str == "LIST_CLUSTERS") return MessageType::LIST_CLUSTERS;
        if (type_str == "CLUSTER_CREATED") return MessageType::CLUSTER_CREATED;
        if (type_str == "CLUSTER_JOINED") return MessageType::CLUSTER_JOINED;
        if (type_str == "CLUSTER_LIST") return MessageType::CLUSTER_LIST;
        if (type_str == "CLUSTER_READY") return MessageType::CLUSTER_READY;
        if (type_str == "ERROR") return MessageType::ERROR;
        if (type_str == "LEAVE_CLUSTER") return MessageType::LEAVE_CLUSTER;
        if (type_str == "SEND_MESSAGE") return MessageType::SEND_MESSAGE;
        if (type_str == "MESSAGE_SHARE") return MessageType::MESSAGE_SHARE;
        if (type_str == "MESSAGE_RECEIVED") return MessageType::MESSAGE_RECEIVED;
        if (type_str == "GET_CLUSTER_MEMBERS") return MessageType::GET_CLUSTER_MEMBERS;
        if (type_str == "CLUSTER_MEMBERS") return MessageType::CLUSTER_MEMBERS;
        if (type_str == "REGISTER_P2P_PORT") return MessageType::REGISTER_P2P_PORT;
        if (type_str == "GET_CLIENT_INFO") return MessageType::GET_CLIENT_INFO;
        if (type_str == "CLIENT_INFO") return MessageType::CLIENT_INFO;
        if (type_str == "SHARE_POOL_ADD") return MessageType::SHARE_POOL_ADD;
        if (type_str == "SHARE_POOL_CLAIM") return MessageType::SHARE_POOL_CLAIM;
        if (type_str == "SHARE_POOL_ACK") return MessageType::SHARE_POOL_ACK;
        if (type_str == "SHARE_POOL_UNFREEZE") return MessageType::SHARE_POOL_UNFREEZE;
        if (type_str == "SHARE_POOL_REMOVE") return MessageType::SHARE_POOL_REMOVE;
        
        return MessageType::ERROR;
    }
    
    static std::vector<std::string> parse_params(const std::string& message) {
        std::vector<std::string> params;
        std::istringstream iss(message);
        std::string token;
        
        bool first = true;
        while (std::getline(iss, token, '|')) {
            if (first) {
                first = false;
                continue;  
            }
            params.push_back(token);
        }
        
        return params;
    }
    
    static std::string cluster_created(const std::string& cluster_id) {
        return "CLUSTER_CREATED|" + cluster_id;
    }
    
    static std::string cluster_joined(const std::string& cluster_id) {
        return "CLUSTER_JOINED|" + cluster_id;
    }
    
    static std::string cluster_ready(const std::string& cluster_id) {
        return "CLUSTER_READY|" + cluster_id;
    }
    
    static std::string error(const std::string& error_msg) {
        return "ERROR|" + error_msg;
    }
    
    static std::string cluster_list(const std::vector<std::string>& cluster_data) {
        std::string result = "CLUSTER_LIST";
        for (const auto& data : cluster_data) {
            result += "|" + data;
        }
        return result;
    }
};

} 
} 
} 

