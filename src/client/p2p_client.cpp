#include "p2p_client.hpp"
#include <vmdt/p2p_protocol.hpp>
#include <vmdt/ssms.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <iostream>
#include <random>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <map>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <fstream>
#include <filesystem>

namespace vmdt {
namespace p2p {

P2PClient::P2PClient(const std::string& server_host, uint16_t server_port)
    : server_host_(server_host), server_port_(server_port), socket_fd_(-1),
      connected_(false), cluster_ready_(false), cluster_n_(0), cluster_k_(0),
      p2p_listen_socket_(-1), p2p_port_(0), p2p_listening_(false) {
    client_id_ = generate_client_id();
}

P2PClient::~P2PClient() {
    disconnect();
}

std::string P2PClient::generate_client_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(10000, 99999);
    return "client_" + std::to_string(dis(gen));
}

bool P2PClient::connect() {
    socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd_ < 0) {
//         std::cerr << "[CLIENT] Error creating socket\n";
        return false;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port_);
    
    
    if (inet_pton(AF_INET, server_host_.c_str(), &server_addr.sin_addr) <= 0) {
        
        struct hostent* host_entry = gethostbyname(server_host_.c_str());
        if (host_entry == nullptr) {
//             std::cerr << "[CLIENT] Invalid server address or hostname: " << server_host_ << "\n";
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }
        
        memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    }
    
    if (::connect(socket_fd_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
//         std::cerr << "[CLIENT] Error connecting to server\n";
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }
    
    connected_ = true;
//     std::cout << "[CLIENT] Connected to server as " << client_id_ << "\n";
    start_p2p_listener();
    return true;
}

void P2PClient::disconnect() {
    if (connected_ && socket_fd_ >= 0) {
        if (!my_cluster_id_.empty()) {
            send_request(protocol::Message::leave_cluster(client_id_));
        }
        close(socket_fd_);
        socket_fd_ = -1;
        connected_ = false;
        my_cluster_id_.clear();
        cluster_ready_ = false;
    }
    stop_p2p_listener();
}

std::string P2PClient::send_request(const std::string& request) {
    if (!connected_ || socket_fd_ < 0) {
        return "";
    }
    
    std::string message = request + "\n";
    
    ssize_t bytes_sent = send(socket_fd_, message.c_str(), message.length(), 0);
    if (bytes_sent < 0) {
        return "";
    }
    
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    
    struct pollfd pfd;
    pfd.fd = socket_fd_;
    pfd.events = POLLIN;
    
    int poll_result = poll(&pfd, 1, 5000);
    
    if (poll_result > 0 && (pfd.revents & POLLIN)) {
        ssize_t bytes_received = recv(socket_fd_, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received > 0) {
            std::string response(buffer, bytes_received);
            
            if (!response.empty() && response.back() == '\n') {
                response.pop_back();
            }
            return response;
        } else if (bytes_received == 0) {
            connected_ = false;
        }
    }
    
    return "";
}

std::string P2PClient::create_cluster(int n, int k) {
    if (!connected_) {
        return "";
    }
    
    std::string response = send_request(protocol::Message::create_cluster(client_id_, n, k));
    
    if (response.empty()) {
        return "";
    }
    
    size_t newline_pos = response.find('\n');
    std::string first_line = response;
    if (newline_pos != std::string::npos) {
        first_line = response.substr(0, newline_pos);
    }
    
    protocol::MessageType type = protocol::Message::parse_type(first_line);
    
    if (type == protocol::MessageType::CLUSTER_CREATED) {
        std::vector<std::string> params = protocol::Message::parse_params(first_line);
        if (!params.empty()) {
            my_cluster_id_ = params[0];
            cluster_n_ = 0;
            cluster_k_ = 0;
            
            auto clusters = list_clusters();
            for (const auto& cluster : clusters) {
                if (cluster.cluster_id == my_cluster_id_) {
                    cluster_n_ = cluster.n;
                    cluster_k_ = cluster.k;
                    break;
                }
            }
            std::cout << "\033[32m[CLIENT]\033[0m Created cluster: \033[36m" << my_cluster_id_ << "\033[0m\n";
            return my_cluster_id_;
        }
    } else if (type == protocol::MessageType::ERROR) {
        std::vector<std::string> params = protocol::Message::parse_params(first_line);
        if (!params.empty()) {
            std::cerr << "\033[31m[CLIENT]\033[0m " << params[0] << "\n";
        }
    }
    
    return "";
}

bool P2PClient::join_cluster(const std::string& cluster_id) {
    if (!connected_) {
        return false;
    }
    
    std::string response = send_request(protocol::Message::join_cluster(client_id_, cluster_id));
    
    if (response.empty()) {
        return false;
    }
    
    std::istringstream iss(response);
    std::string line;
    bool joined = false;
    
    while (std::getline(iss, line)) {
        protocol::MessageType type = protocol::Message::parse_type(line);
        if (type == protocol::MessageType::CLUSTER_JOINED) {
            std::vector<std::string> params = protocol::Message::parse_params(line);
            if (!params.empty()) {
                my_cluster_id_ = params[0];
                joined = true;
                
                auto clusters = list_clusters();
                for (const auto& cluster : clusters) {
                    if (cluster.cluster_id == my_cluster_id_) {
                        cluster_n_ = cluster.n;
                        cluster_k_ = cluster.k;
                        break;
                    }
                }
                std::cout << "\033[32m[CLIENT]\033[0m Joined cluster: \033[36m" << my_cluster_id_ << "\033[0m\n";
            }
        } else if (type == protocol::MessageType::CLUSTER_READY) {
            std::vector<std::string> params = protocol::Message::parse_params(line);
            if (!params.empty()) {
                cluster_ready_ = true;
                std::cout << "\033[32m[CLIENT]\033[0m Cluster ready!\n";
            }
        } else if (type == protocol::MessageType::ERROR) {
            std::vector<std::string> params = protocol::Message::parse_params(line);
            if (!params.empty()) {
                std::cerr << "\033[31m[CLIENT]\033[0m " << params[0] << "\n";
            }
        }
    }
    
    return joined;
}

bool P2PClient::leave_cluster() {
    if (!connected_ || my_cluster_id_.empty()) {
        return false;
    }
    
    std::string response = send_request(protocol::Message::leave_cluster(client_id_));
    
    if (response.empty()) {
        return false;
    }
    
    size_t newline_pos = response.find('\n');
    if (newline_pos != std::string::npos) {
        response = response.substr(0, newline_pos);
    }
    
    if (response.find("OK") != std::string::npos) {
        std::cout << "\033[33m[CLIENT]\033[0m Left cluster\n";
        my_cluster_id_.clear();
        cluster_ready_ = false;
        return true;
    }
    
    return false;
}

std::vector<ClusterInfo> P2PClient::list_clusters() {
    std::vector<ClusterInfo> clusters;
    
    if (!connected_) {
        return clusters;
    }
    
    std::string response = send_request(protocol::Message::list_clusters(client_id_));
    
    if (response.empty()) {
        return clusters;
    }
    
    std::istringstream iss(response);
    std::string line;
    std::string cluster_list_line;
    
    while (std::getline(iss, line)) {
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);
        
        if (line.empty()) continue;
        
        protocol::MessageType type = protocol::Message::parse_type(line);
        
        if (type == protocol::MessageType::CLUSTER_LIST) {
            cluster_list_line = line;
            break;
        } else if (type == protocol::MessageType::CLUSTER_READY) {
            std::vector<std::string> params = protocol::Message::parse_params(line);
            if (!params.empty() && params[0] == my_cluster_id_) {
                cluster_ready_ = true;
            }
        }
    }
    
    if (cluster_list_line.empty()) {
        std::string trimmed_response = response;
        trimmed_response.erase(0, trimmed_response.find_first_not_of(" \t\n\r"));
        trimmed_response.erase(trimmed_response.find_last_not_of(" \t\n\r") + 1);
        protocol::MessageType type = protocol::Message::parse_type(trimmed_response);
        if (type == protocol::MessageType::CLUSTER_LIST) {
            cluster_list_line = trimmed_response;
        } else {
            return clusters;
        }
    }
    
    protocol::MessageType type = protocol::Message::parse_type(cluster_list_line);
    if (type == protocol::MessageType::CLUSTER_LIST) {
        std::vector<std::string> params = protocol::Message::parse_params(cluster_list_line);
        
        for (const auto& param : params) {
            if (param.empty()) continue;
            
            std::istringstream iss(param);
            std::string token;
            std::vector<std::string> parts;
            
            while (std::getline(iss, token, ':')) {
                parts.push_back(token);
            }
            
            if (parts.size() >= 6) {
                ClusterInfo info;
                info.cluster_id = parts[0];
                info.creator_id = parts[1];
                info.n = std::stoi(parts[2]);
                info.k = std::stoi(parts[3]);
                info.current_members = std::stoi(parts[4]);
                info.is_active = (parts[5] == "1");
                clusters.push_back(info);
            }
        }
    }
    
    return clusters;
}

bool P2PClient::is_cluster_ready() {
    if (!connected_ || my_cluster_id_.empty()) {
        return false;
    }
    
    
    auto clusters = list_clusters();
    for (const auto& cluster : clusters) {
        if (cluster.cluster_id == my_cluster_id_) {
            cluster_ready_ = cluster.is_active;
            cluster_n_ = cluster.n;
            cluster_k_ = cluster.k;
            return cluster.is_active;
        }
    }
    
    return false;
}

std::vector<std::string> P2PClient::get_cluster_members() {
    std::vector<std::string> members;
    
    if (!connected_ || my_cluster_id_.empty()) {
        return members;
    }
    
    std::string response = send_request(protocol::Message::get_cluster_members(client_id_));
    
    if (response.empty()) {
        return members;
    }
    
    std::istringstream iss(response);
    std::string line;
    std::string members_line;
    
    while (std::getline(iss, line)) {
        protocol::MessageType type = protocol::Message::parse_type(line);
        if (type == protocol::MessageType::CLUSTER_MEMBERS) {
            members_line = line;
            break;
        }
    }
    
    if (members_line.empty()) {
        return members;
    }
    
    protocol::MessageType type = protocol::Message::parse_type(members_line);
    if (type == protocol::MessageType::CLUSTER_MEMBERS) {
        std::vector<std::string> params = protocol::Message::parse_params(members_line);
        members = params;
    }
    
    return members;
}


std::string P2PClient::base64_encode(const std::vector<uint8_t>& data) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    int val = 0, valb = -6;
    
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    
    return encoded;
}


std::vector<uint8_t> P2PClient::base64_decode(const std::string& encoded) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> decoded;
    int val = 0, valb = -8;
    
    for (char c : encoded) {
        if (c == '=') break;
        const char* pos = strchr(base64_chars, c);
        if (pos == nullptr) continue;
        val = (val << 6) + (pos - base64_chars);
        valb += 6;
        if (valb >= 0) {
            decoded.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    
    return decoded;
}

bool P2PClient::send_message(const std::string& target_client_id, const std::string& message) {
    if (!connected_ || my_cluster_id_.empty()) {
        return false;
    }
    
    if (!is_cluster_ready()) {
        std::cerr << "\033[33m[CLIENT]\033[0m Cluster not ready yet\n";
        return false;
    }
    
    std::vector<std::string> members = get_cluster_members();
    if (members.empty() || static_cast<int>(members.size()) < cluster_n_ + 1) {
        std::cerr << "\033[33m[CLIENT]\033[0m Not enough members in cluster\n";
        return false;
    }
    
    std::string trimmed_message = message;
    trimmed_message.erase(0, trimmed_message.find_first_not_of(" \t\n\r"));
    trimmed_message.erase(trimmed_message.find_last_not_of(" \t\n\r") + 1);
    
    std::error_code ec;
    if (std::filesystem::exists(trimmed_message, ec) && std::filesystem::is_regular_file(trimmed_message, ec)) {
        return send_file(target_client_id, trimmed_message);
    }
    
    
    std::vector<uint8_t> message_bytes(message.begin(), message.end());
    
    
    using namespace vmdt::crypto;
    std::vector<std::vector<uint8_t>> share_vectors;
    try {
        share_vectors = SSMS::split_simple(message_bytes, cluster_k_, cluster_n_);
    } catch (const std::exception& e) {
        std::cerr << "\033[31m[CLIENT]\033[0m Error: " << e.what() << "\n";
        return false;
    }
    
    
    std::string message_id = client_id_ + "_" + target_client_id + "_" + std::to_string(time(nullptr));
    
    
    
    std::vector<std::pair<int, std::string>> all_encoded_shares;
    for (size_t i = 0; i < share_vectors.size(); ++i) {
        std::string encoded_share = base64_encode(share_vectors[i]);
        all_encoded_shares.push_back({static_cast<int>(i), encoded_share});
    }
    
    if (!broadcast_share_pool_add(message_id, client_id_, target_client_id, all_encoded_shares, cluster_k_, false, "")) {
        std::cerr << "\033[31m[CLIENT]\033[0m Failed to send message\n";
        return false;
    }
    
    std::cout << "\033[32m[CLIENT]\033[0m Message sent to " << target_client_id << "\n";
    return true;
}

bool P2PClient::send_file(const std::string& target_client_id, const std::string& filepath) {
    if (!connected_ || my_cluster_id_.empty() || !is_cluster_ready()) {
        return false;
    }
    
    std::vector<std::string> members = get_cluster_members();
    if (members.empty() || static_cast<int>(members.size()) < cluster_n_ + 1) {
        std::cerr << "\033[33m[CLIENT]\033[0m Not enough members\n";
        return false;
    }
    
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "\033[31m[CLIENT]\033[0m Cannot open file\n";
        return false;
    }
    
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<uint8_t> file_data(file_size);
    file.read(reinterpret_cast<char*>(file_data.data()), file_size);
    file.close();
    
    std::filesystem::path path_obj(filepath);
    std::string filename = path_obj.filename().string();
    
    using namespace vmdt::crypto;
    std::vector<std::vector<uint8_t>> share_vectors;
    try {
        share_vectors = SSMS::split_simple(file_data, cluster_k_, cluster_n_);
    } catch (const std::exception& e) {
        std::cerr << "\033[31m[CLIENT]\033[0m Error: " << e.what() << "\n";
        return false;
    }
    
    std::string message_id = client_id_ + "_" + target_client_id + "_" + std::to_string(time(nullptr));
    
    std::vector<std::pair<int, std::string>> all_encoded_shares;
    for (size_t i = 0; i < share_vectors.size(); ++i) {
        std::string encoded_share = base64_encode(share_vectors[i]);
        all_encoded_shares.push_back({static_cast<int>(i), encoded_share});
    }
    
    if (!broadcast_share_pool_add(message_id, client_id_, target_client_id, all_encoded_shares, cluster_k_, true, filename)) {
        std::cerr << "\033[31m[CLIENT]\033[0m Failed to send file\n";
        return false;
    }
    
    std::cout << "\033[32m[CLIENT]\033[0m File \"" << filename << "\" sent to " << target_client_id << "\n";
    return true;
}

void P2PClient::check_for_messages() {
    if (!connected_ || socket_fd_ < 0) {
        return;  
    }
    
    if (my_cluster_id_.empty()) {
        return;  
    }
    
    
    process_p2p_connections();
    
    int messages_processed = 0;
    
    
    while (true) {
        struct pollfd pfd;
        pfd.fd = socket_fd_;
        pfd.events = POLLIN;
        
        
        int poll_result = poll(&pfd, 1, 0);
        
        if (poll_result <= 0 || !(pfd.revents & POLLIN)) {
            break;  
        }
        
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        
        
        int flags = fcntl(socket_fd_, F_GETFL, 0);
        fcntl(socket_fd_, F_SETFL, flags | O_NONBLOCK);
        
        ssize_t bytes_received = recv(socket_fd_, buffer, sizeof(buffer) - 1, 0);
        
        
        fcntl(socket_fd_, F_SETFL, flags);
        
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                connected_ = false;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            break;
        }
        
        std::string raw_message(buffer, bytes_received);
        
        
        std::istringstream iss(raw_message);
        std::string line;
        
        while (std::getline(iss, line)) {
            if (line.empty()) continue;
            
            
            line.erase(0, line.find_first_not_of(" \t\n\r"));
            line.erase(line.find_last_not_of(" \t\n\r") + 1);
            
            if (line.empty()) continue;
            
            protocol::MessageType type = protocol::Message::parse_type(line);
            
            if (type == protocol::MessageType::MESSAGE_SHARE) {
                handle_message_share(line);
                messages_processed++;
            } else if (type == protocol::MessageType::CLUSTER_READY) {
                std::vector<std::string> params = protocol::Message::parse_params(line);
                if (!params.empty() && params[0] == my_cluster_id_) {
                    cluster_ready_ = true;
                    std::cout << "\033[32m[CLIENT]\033[0m Cluster ready!\n";
                    messages_processed++;
                }
            }
        }
        
        if (messages_processed > 100) {
            break;
        }
    }
    
    
    for (auto& [message_id, entry] : share_pool_) {
        if (entry.receiver_id == client_id_) {
            
            
            
            int current_count = message_share_counts_.count(message_id) ? message_share_counts_[message_id] : 0;
            int needed = cluster_n_ - current_count;  
            if (needed > 0) {
                for (auto& [share_index, share_pair] : entry.shares) {
                    if (share_pair.first == ShareState::ACTIVE && needed > 0) {
                        if (claim_share_from_pool(message_id, share_index)) {
                            needed--;
                        }
                    }
                }
                
                if (needed > 0 && entry.frozen_count > 0) {
                    
                    for (auto& [share_index, share_pair] : entry.shares) {
                        if (share_pair.first == ShareState::FROZEN && needed > 0) {
                            share_pair.first = ShareState::ACTIVE;
                            entry.frozen_count--;
                            entry.active_count++;
                            if (claim_share_from_pool(message_id, share_index)) {
                                needed--;
                            }
                        }
                    }
                }
            }
        }
    }
}

void P2PClient::handle_message_share(const std::string& message) {
    std::vector<std::string> params = protocol::Message::parse_params(message);
    if (params.size() < 5) {
        return;
    }
    
    std::string from_client = params[0];
    std::string to_client = params[1];
    std::string target_client = params[2];
    int share_index;
    
    try {
        share_index = std::stoi(params[3]);
    } catch (const std::exception& e) {
        return;
    }
    
    std::string encoded_share = params[4];
    
    if (to_client != client_id_) {
        return;
    }
    
    if (target_client == client_id_) {
        std::vector<uint8_t> share_data = base64_decode(encoded_share);
        
        if (share_data.size() < 10) {
            return;
        }
        
        std::string message_id = from_client + "_" + target_client;
        
        
        if (pending_shares_[message_id].find(share_index) != pending_shares_[message_id].end()) {
            return;
        }
        
        pending_shares_[message_id][share_index] = share_data;
        message_share_counts_[message_id]++;
        
        int total_shares = message_share_counts_[message_id];
//         std::cout << "[CLIENT] ✓ Share " << share_index << " stored. Total: " << total_shares 
//                   << "/" << cluster_k_ << " shares collected (from " << from_client << ")\n";
        
        if (total_shares >= cluster_k_) {
            reconstruct_message(message_id);
        }
    }
}

void P2PClient::reconstruct_message(const std::string& message_id) {
    if (pending_shares_.find(message_id) == pending_shares_.end()) {
        std::cerr << "[CLIENT] No pending shares for message: " << message_id << "\n";
        return;
    }
    
    auto& shares_map = pending_shares_[message_id];
    
    if (static_cast<int>(shares_map.size()) < cluster_k_) {
        std::cerr << "[CLIENT] Not enough shares for reconstruction. Have: " << shares_map.size() 
                  << ", Need: " << cluster_k_ << " (k-of-n threshold)\n";
        return;
    }
    
//     std::cout << "[CLIENT] Starting SSMS reconstruction with " << shares_map.size() << " shares (need k=" << cluster_k_ << ")...\n";
    
    using namespace vmdt::crypto;
    
    std::vector<std::vector<uint8_t>> share_vectors;
    for (const auto& [index, share_data] : shares_map) {
        if (share_data.size() < 10) {
            std::cerr << "[CLIENT] ✗ Invalid share data size for share " << index << "\n";
            continue;
        }
        share_vectors.push_back(share_data);
        uint8_t stored_index = share_data[0];
//         std::cout << "[CLIENT]   Share " << index << ": size=" << share_data.size() 
//                   << " bytes, index_byte=" << (int)stored_index << "\n";
        
        if (static_cast<int>(share_vectors.size()) >= cluster_k_) {
            break;
        }
    }
    
    if (static_cast<int>(share_vectors.size()) < cluster_k_) {
        std::cerr << "[CLIENT] ✗ Not enough valid shares. Have: " << share_vectors.size() 
                  << ", Need: " << cluster_k_ << "\n";
        return;
    }
    
    try {
        
        
        
//         std::cout << "[CLIENT] Calling SSMS::reconstruct_simple with " << share_vectors.size() 
//                   << " shares (n=" << cluster_n_ << ", k=" << cluster_k_ << ")...\n";
//         std::cout << "[CLIENT] Share order verification:\n";
//         for (size_t i = 0; i < share_vectors.size(); ++i) {
//             if (share_vectors[i].size() > 0) {
//                 uint8_t index_byte = share_vectors[i][0];
//                 std::cout << "  Position " << i << ": index_byte=" << (int)index_byte 
//                           << " (expected " << (i + 1) << ")\n";
//                 if (index_byte != static_cast<uint8_t>(i + 1)) {
//                     std::cerr << "[CLIENT] ⚠ WARNING: Share at position " << i 
//                               << " has wrong index byte! This may cause reconstruction to fail.\n";
//                 }
//             }
//         }
        
        std::vector<uint8_t> reconstructed = SSMS::reconstruct_simple(share_vectors);
        
        bool is_file = false;
        std::string original_filename = "";
        if (pending_file_metadata_.find(message_id) != pending_file_metadata_.end()) {
            is_file = pending_file_metadata_[message_id].first;
            original_filename = pending_file_metadata_[message_id].second;
        }
        
        size_t underscore_pos = message_id.find('_');
        std::string sender_id = (underscore_pos != std::string::npos) ? 
                               message_id.substr(0, underscore_pos) : message_id;
        
        std::string output_filename;
        if (is_file) {
            std::cout << "\033[36m[MSG]\033[0m File from \033[33m" << sender_id << "\033[0m: " << original_filename << "\n";
            
            std::cout << "Save as [" << original_filename << "]: ";
            std::string user_filename;
            std::getline(std::cin, user_filename);
            
            output_filename = user_filename.empty() ? original_filename : user_filename;
            SSMS::write_file(output_filename, reconstructed);
            std::cout << "\033[32m[MSG]\033[0m Saved: " << output_filename << "\n";
        } else {
            std::string message(reconstructed.begin(), reconstructed.end());
            std::cout << "\033[36m[MSG]\033[0m From \033[33m" << sender_id << "\033[0m: " << message << "\n";
        }
        
        pending_shares_.erase(message_id);
        message_share_counts_.erase(message_id);
        pending_file_metadata_.erase(message_id);
    } catch (const std::exception& e) {
        std::cerr << "\033[31m[CLIENT]\033[0m Decryption failed: " << e.what() << "\n";
    }
}

bool P2PClient::start_p2p_listener() {
    if (p2p_listening_) {
        return true;  
    }
    
    p2p_listen_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (p2p_listen_socket_ < 0) {
        return false;
    }
    
    int opt = 1;
    setsockopt(p2p_listen_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    
    const uint16_t P2P_PORT_MIN = 9000;
    const uint16_t P2P_PORT_MAX = 10000;
    bool bound = false;
    
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(P2P_PORT_MIN, P2P_PORT_MAX);
    uint16_t start_port = static_cast<uint16_t>(dis(gen));
    
    
    for (uint16_t offset = 0; offset <= (P2P_PORT_MAX - P2P_PORT_MIN); ++offset) {
        uint16_t try_port = static_cast<uint16_t>(start_port + offset);
        if (try_port > P2P_PORT_MAX) {
            try_port = static_cast<uint16_t>(P2P_PORT_MIN + (try_port - P2P_PORT_MAX - 1));
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(try_port);
        
        if (bind(p2p_listen_socket_, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            p2p_port_ = try_port;
            bound = true;
            break;
        }
    }
    
    if (!bound) {
        close(p2p_listen_socket_);
        p2p_listen_socket_ = -1;
        return false;
    }
    
    if (listen(p2p_listen_socket_, 10) < 0) {
        close(p2p_listen_socket_);
        p2p_listen_socket_ = -1;
        return false;
    }
    
    
    int flags = fcntl(p2p_listen_socket_, F_GETFL, 0);
    fcntl(p2p_listen_socket_, F_SETFL, flags | O_NONBLOCK);
    
    p2p_listening_ = true;
    
    if (connected_) {
        send_request(protocol::Message::register_p2p_port(client_id_, p2p_port_));
    }
    
    return true;
}

void P2PClient::stop_p2p_listener() {
    if (p2p_listen_socket_ >= 0) {
        close(p2p_listen_socket_);
        p2p_listen_socket_ = -1;
    }
    p2p_listening_ = false;
    p2p_port_ = 0;
}

std::pair<std::string, uint16_t> P2PClient::get_client_info(const std::string& target_client_id) {
    if (!connected_) {
        return {"", 0};
    }
    
    std::string response = send_request(protocol::Message::get_client_info(client_id_, target_client_id));
    
    if (response.empty()) {
        return {"", 0};
    }
    
    protocol::MessageType type = protocol::Message::parse_type(response);
    if (type == protocol::MessageType::CLIENT_INFO) {
        std::vector<std::string> params = protocol::Message::parse_params(response);
        if (params.size() >= 2) {
            std::string ip = params[0];
            uint16_t port = static_cast<uint16_t>(std::stoi(params[1]));
            return {ip, port};
        }
    }
    
    return {"", 0};
}

bool P2PClient::send_share_to_peer(const std::string& peer_ip, uint16_t peer_port,
                                   const std::string& from_client, const std::string& to_client,
                                   const std::string& target_client, int share_index,
                                   const std::string& encoded_share) {
    int peer_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_socket < 0) {
        return false;
    }
    
    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer_port);
    
    if (inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr) <= 0) {
        close(peer_socket);
        return false;
    }
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(peer_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(peer_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    if (::connect(peer_socket, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) < 0) {
        close(peer_socket);
        return false;
    }
    
    std::string message = protocol::Message::message_share(from_client, to_client, target_client, 
                                                           share_index, encoded_share);
    message += "\n";
    
    send(peer_socket, message.c_str(), message.length(), 0);
    close(peer_socket);
    
    return true;
}

void P2PClient::process_p2p_connections() {
    if (!p2p_listening_ || p2p_listen_socket_ < 0) {
        return;
    }
    
    
    for (int i = 0; i < 10; ++i) {
        
        struct pollfd pfd;
        pfd.fd = p2p_listen_socket_;
        pfd.events = POLLIN;
        
        int poll_result = poll(&pfd, 1, 0);
        if (poll_result <= 0 || !(pfd.revents & POLLIN)) {
            break;  
        }
        
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_socket = accept(p2p_listen_socket_, (struct sockaddr*)&client_addr, &addr_len);
        
        if (client_socket < 0) {
            break;
        }
        
        
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        close(client_socket);
        
        if (bytes_received <= 0) {
            continue;
        }
        
        std::string message(buffer, bytes_received);
        
        if (!message.empty() && message.back() == '\n') {
            message.pop_back();
        }
        
        protocol::MessageType type = protocol::Message::parse_type(message);
        switch (type) {
            case protocol::MessageType::MESSAGE_SHARE:
                handle_message_share(message);
                break;
            case protocol::MessageType::SHARE_POOL_ADD:
                handle_share_pool_add(message);
                break;
            case protocol::MessageType::SHARE_POOL_CLAIM:
                handle_share_pool_claim(message);
                break;
            case protocol::MessageType::SHARE_POOL_ACK:
                handle_share_pool_ack(message);
                break;
            case protocol::MessageType::SHARE_POOL_UNFREEZE:
                handle_share_pool_unfreeze(message);
                break;
            case protocol::MessageType::SHARE_POOL_REMOVE:
                handle_share_pool_remove(message);
                break;
            default:
                break;
        }
    }
}

bool P2PClient::send_to_all_cluster_members(const std::string& message) {
    std::vector<std::string> members = get_cluster_members();
    if (members.empty()) {
        return false;
    }
    
    bool all_sent = true;
    for (const auto& member_id : members) {
        if (member_id == client_id_) {
            continue;  
        }
        
        auto [peer_ip, peer_port] = get_client_info(member_id);
        if (peer_ip.empty() || peer_port == 0) {
            all_sent = false;
            continue;
        }
        
        int peer_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (peer_socket < 0) {
            all_sent = false;
            continue;
        }
        
        struct sockaddr_in peer_addr;
        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(peer_port);
        inet_pton(AF_INET, peer_ip.c_str(), &peer_addr.sin_addr);
        
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;
        setsockopt(peer_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        if (::connect(peer_socket, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == 0) {
            std::string msg = message + "\n";
            send(peer_socket, msg.c_str(), msg.length(), 0);
        }
        close(peer_socket);
    }
    
    return all_sent;
}

bool P2PClient::broadcast_share_pool_add(const std::string& message_id, const std::string& sender_id,
                                  const std::string& receiver_id, 
                                  const std::vector<std::pair<int, std::string>>& all_shares,
                                  int k_threshold, bool is_file, const std::string& filename) {
    
    SharePoolEntry entry;
    entry.sender_id = sender_id;
    entry.receiver_id = receiver_id;
    entry.active_count = k_threshold;
    entry.frozen_count = static_cast<int>(all_shares.size()) - k_threshold;
    entry.claimed_count = 0;
    
    
    for (size_t i = 0; i < all_shares.size(); ++i) {
        ShareState state = (i < static_cast<size_t>(k_threshold)) ? ShareState::ACTIVE : ShareState::FROZEN;
        entry.shares[all_shares[i].first] = {state, all_shares[i].second};
    }
    
    share_pool_[message_id] = entry;
    
    
    std::string pool_msg = protocol::Message::share_pool_add(message_id, sender_id, receiver_id,
                                                             static_cast<int>(all_shares.size()),
                                                             k_threshold, all_shares, is_file, filename);
    return send_to_all_cluster_members(pool_msg);
}

void P2PClient::handle_share_pool_add(const std::string& message) {
    std::vector<std::string> params = protocol::Message::parse_params(message);
    if (params.size() < 6) {
        return;
    }
    
    std::string message_id = params[0];
    std::string sender_id = params[1];
    std::string receiver_id = params[2];
    int total_shares = std::stoi(params[3]);
    int active_shares = std::stoi(params[4]);
    
    bool is_file = false;
    std::string filename = "";
    size_t shares_start_idx = 5;
    
    if (params.size() >= 7 && (params[5] == "FILE" || params[5] == "TEXT")) {
        is_file = (params[5] == "FILE");
        filename = params[6];
        shares_start_idx = 7;
    }
    
    std::vector<std::pair<int, std::string>> shares;
    for (size_t i = shares_start_idx; i < params.size(); ++i) {
        size_t colon_pos = params[i].find(':');
        if (colon_pos != std::string::npos) {
            int index = std::stoi(params[i].substr(0, colon_pos));
            std::string share_data = params[i].substr(colon_pos + 1);
            shares.push_back({index, share_data});
        }
    }
    
    
    SharePoolEntry entry;
    entry.sender_id = sender_id;
    entry.receiver_id = receiver_id;
    entry.active_count = active_shares;
    entry.frozen_count = total_shares - active_shares;
    entry.claimed_count = 0;
    entry.is_file = is_file;
    entry.filename = filename;
    
    
    for (size_t i = 0; i < shares.size(); ++i) {
        ShareState state = (i < static_cast<size_t>(active_shares)) ? ShareState::ACTIVE : ShareState::FROZEN;
        entry.shares[shares[i].first] = {state, shares[i].second};
    }
    
    share_pool_[message_id] = entry;
    
    if (receiver_id == client_id_) {
        int claimed = 0;
        
        for (const auto& [index, share_pair] : entry.shares) {
            if (share_pair.first == ShareState::ACTIVE && claimed < cluster_k_) {
                if (claim_share_from_pool(message_id, index)) {
                    claimed++;
                }
            }
        }
        
        if (claimed < cluster_k_) {
            for (auto& [index, share_pair] : entry.shares) {
                if (share_pair.first == ShareState::FROZEN && claimed < cluster_k_) {
                    share_pair.first = ShareState::ACTIVE;
                    entry.frozen_count--;
                    entry.active_count++;
                    if (claim_share_from_pool(message_id, index)) {
                        claimed++;
                    }
                }
            }
        }
    }
}

void P2PClient::handle_share_pool_claim(const std::string& message) {
    std::vector<std::string> params = protocol::Message::parse_params(message);
    if (params.size() < 3) {
        return;
    }
    
    std::string message_id = params[0];
    std::string claimer_id = params[1];
    int share_index = std::stoi(params[2]);
    
    auto it = share_pool_.find(message_id);
    if (it == share_pool_.end()) {
        return;
    }
    
    SharePoolEntry& entry = it->second;
    
    
    auto share_it = entry.shares.find(share_index);
    if (share_it == entry.shares.end()) {
        return;
    }
    
    
    if (claimer_id == entry.sender_id || claimer_id == entry.receiver_id) {
        return;  
    }
    
    
    if (share_it->second.first != ShareState::ACTIVE) {
        return;
    }
    
    share_it->second.first = ShareState::CLAIMED;
    entry.active_count--;
    entry.claimed_count++;
}

bool P2PClient::claim_share_from_pool(const std::string& message_id, int share_index) {
    auto it = share_pool_.find(message_id);
    if (it == share_pool_.end()) {
        return false;
    }
    
    SharePoolEntry& entry = it->second;
    
    
    if (client_id_ == entry.sender_id || client_id_ == entry.receiver_id) {
        
        if (client_id_ == entry.sender_id) {
            return false;  
        }
        
    }
    
    auto share_it = entry.shares.find(share_index);
    if (share_it == entry.shares.end()) {
        return false;
    }
    
    
    if (share_it->second.first != ShareState::ACTIVE) {
        return false;
    }
    
    
    share_it->second.first = ShareState::CLAIMED;
    entry.active_count--;
    entry.claimed_count++;
    
    
    std::string claim_msg = protocol::Message::share_pool_claim(message_id, client_id_, share_index);
    send_to_all_cluster_members(claim_msg);
    
    
        if (client_id_ == entry.receiver_id) {
        std::vector<uint8_t> share_data = base64_decode(share_it->second.second);
        
        
        std::string msg_id = message_id;  
        pending_shares_[msg_id][share_index] = share_data;
        message_share_counts_[msg_id]++;
        
        pending_file_metadata_[msg_id] = {entry.is_file, entry.filename};
        
        if (message_share_counts_[message_id] >= cluster_k_) {
            reconstruct_message(message_id);
            send_ack_to_sender(message_id);
        }
    }
    
    return true;
}

void P2PClient::send_ack_to_sender(const std::string& message_id) {
    auto it = share_pool_.find(message_id);
    if (it == share_pool_.end()) {
        return;
    }
    
    SharePoolEntry& entry = it->second;
    
    
    auto [sender_ip, sender_port] = get_client_info(entry.sender_id);
    if (!sender_ip.empty() && sender_port > 0) {
        std::string ack_msg = protocol::Message::share_pool_ack(message_id, client_id_);
        int peer_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (peer_socket >= 0) {
            struct sockaddr_in peer_addr;
            memset(&peer_addr, 0, sizeof(peer_addr));
            peer_addr.sin_family = AF_INET;
            peer_addr.sin_port = htons(sender_port);
            inet_pton(AF_INET, sender_ip.c_str(), &peer_addr.sin_addr);
            
            struct timeval timeout;
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;
            setsockopt(peer_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            
            if (::connect(peer_socket, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == 0) {
                std::string msg = ack_msg + "\n";
                send(peer_socket, msg.c_str(), msg.length(), 0);
            }
            close(peer_socket);
        }
    }
    
    
    std::string remove_msg = protocol::Message::share_pool_remove(message_id);
    send_to_all_cluster_members(remove_msg);
}

void P2PClient::handle_share_pool_ack(const std::string& message) {
    std::vector<std::string> params = protocol::Message::parse_params(message);
    if (params.size() < 2) {
        return;
    }
    
    std::string message_id = params[0];
    std::string receiver_id = params[1];
    
    auto it = share_pool_.find(message_id);
    if (it == share_pool_.end()) {
        return;
    }
    
    
    if (it->second.receiver_id != receiver_id) {
        return;
    }
    
    if (client_id_ == it->second.sender_id) {
        share_pool_.erase(it);
        std::string remove_msg = protocol::Message::share_pool_remove(message_id);
        send_to_all_cluster_members(remove_msg);
    }
}

void P2PClient::handle_share_pool_unfreeze(const std::string& message) {
    std::vector<std::string> params = protocol::Message::parse_params(message);
    if (params.size() < 2) {
        return;
    }
    
    std::string message_id = params[0];
    int share_index = std::stoi(params[1]);
    
    auto it = share_pool_.find(message_id);
    if (it == share_pool_.end()) {
        return;
    }
    
    SharePoolEntry& entry = it->second;
    auto share_it = entry.shares.find(share_index);
    if (share_it != entry.shares.end() && share_it->second.first == ShareState::FROZEN) {
        share_it->second.first = ShareState::ACTIVE;
        entry.frozen_count--;
        entry.active_count++;
    }
}

void P2PClient::handle_share_pool_remove(const std::string& message) {
    std::vector<std::string> params = protocol::Message::parse_params(message);
    if (params.empty()) {
        return;
    }
    
    std::string message_id = params[0];
    share_pool_.erase(message_id);
}

bool P2PClient::reconstruct_from_files(const std::string& base_filename, const std::string& output_filename) {
    using namespace vmdt::crypto;
    
    
    std::vector<std::string> share_filenames;
    for (int i = 1; i <= cluster_n_; ++i) {
        std::string filename = base_filename + "_share" + std::to_string(i) + ".bin";
        share_filenames.push_back(filename);
    }
    
    std::vector<std::vector<uint8_t>> loaded_shares = SSMS::load_shares(share_filenames);
    
    if (loaded_shares.empty()) {
        return false;
    }
    
//     std::cout << "[CLIENT] Loaded " << loaded_shares.size() << " shares from files\n";
    
    if (static_cast<int>(loaded_shares.size()) < cluster_k_) {
        return false;
    }
    
    try {
        std::vector<uint8_t> reconstructed = SSMS::reconstruct_simple(loaded_shares);
        SSMS::write_file(output_filename, reconstructed);
        
        std::string message(reconstructed.begin(), reconstructed.end());
        std::cout << "\033[36m[MSG]\033[0m " << message << "\n";
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "\033[31m[CLIENT]\033[0m Reconstruction failed: " << e.what() << "\n";
        return false;
    }
}

} 
} 



