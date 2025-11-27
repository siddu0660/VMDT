#include "p2p_server.hpp"
#include <vmdt/p2p_protocol.hpp>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <sstream>
#include <iostream>
#include <thread>
#include <random>
#include <errno.h>

namespace vmdt {
namespace p2p {

P2PServer::P2PServer(uint16_t port) : port_(port), server_socket_(-1), running_(false) {
}

P2PServer::~P2PServer() {
    stop();
}

std::string P2PServer::generate_cluster_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    return "cluster_" + std::to_string(dis(gen));
}

void P2PServer::check_cluster_ready(const std::string& cluster_id) {
    
    auto it = clusters_.find(cluster_id);
    if (it != clusters_.end() && it->second) {
        Cluster* cluster = it->second.get();
        if (static_cast<int>(cluster->members.size()) >= cluster->n && !cluster->is_active) {
            cluster->is_active = true;
            std::cout << "\033[32m[SERVER]\033[0m Cluster \033[36m" << cluster_id << "\033[0m ready (" 
                      << cluster->members.size() << "/" << cluster->n << ")\n";
            
            using namespace protocol;
            std::string ready_msg = Message::cluster_ready(cluster_id);
            std::vector<int> sockets_to_notify;
            for (const auto& member_id : cluster->members) {
                auto socket_it = client_to_socket_.find(member_id);
                if (socket_it != client_to_socket_.end()) {
                    sockets_to_notify.push_back(socket_it->second);
                }
            }
            
            for (int socket_fd : sockets_to_notify) {
                std::string msg = ready_msg + "\n";
                send(socket_fd, msg.c_str(), msg.length(), 0);
            }
        }
    }
}

std::string P2PServer::create_cluster(const std::string& client_id, int n, int k) {
    
    std::string cluster_id = generate_cluster_id();
    auto cluster = std::make_unique<Cluster>(cluster_id, client_id, n, k);
    cluster->members.insert(client_id);
    
    clusters_[cluster_id] = std::move(cluster);
    client_to_cluster_[client_id] = cluster_id;
    
    std::cout << "\033[36m[SERVER]\033[0m \033[33m" << client_id << "\033[0m created cluster \033[36m" 
              << cluster_id << "\033[0m (n=" << n << ", k=" << k << ")\n";
    
    check_cluster_ready(cluster_id);
    return cluster_id;
}

bool P2PServer::join_cluster(const std::string& client_id, const std::string& cluster_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    
    if (client_to_cluster_.find(client_id) != client_to_cluster_.end()) {
        return false;
    }
    
    auto it = clusters_.find(cluster_id);
    if (it == clusters_.end() || !it->second) {
        return false;
    }
    
    Cluster* cluster = it->second.get();
    
    
    
    cluster->members.insert(client_id);
    client_to_cluster_[client_id] = cluster_id;
    
    std::cout << "\033[36m[SERVER]\033[0m \033[33m" << client_id << "\033[0m joined cluster \033[36m" 
              << cluster_id << "\033[0m (" << cluster->members.size() << "/" << cluster->n << ")\n";
    
    check_cluster_ready(cluster_id);
    return true;
}

std::vector<Cluster> P2PServer::list_clusters() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Cluster> result;
    
    for (const auto& [id, cluster] : clusters_) {
        if (cluster) {
            result.push_back(*cluster);
        }
    }
    
    return result;
}

Cluster* P2PServer::get_cluster(const std::string& cluster_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = clusters_.find(cluster_id);
    if (it != clusters_.end()) {
        return it->second.get();
    }
    return nullptr;
}

void P2PServer::remove_client(const std::string& client_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = client_to_cluster_.find(client_id);
    if (it != client_to_cluster_.end()) {
        std::string cluster_id = it->second;
        client_to_cluster_.erase(it);
        
        auto cluster_it = clusters_.find(cluster_id);
        if (cluster_it != clusters_.end() && cluster_it->second) {
            cluster_it->second->members.erase(client_id);
            std::cout << "\033[33m[SERVER]\033[0m \033[33m" << client_id << "\033[0m left cluster \033[36m" 
                      << cluster_id << "\033[0m\n";
            
            if (cluster_it->second->members.empty()) {
                clusters_.erase(cluster_it);
            }
        }
    }
    client_to_socket_.erase(client_id);
    client_to_ip_.erase(client_id);
    client_to_p2p_port_.erase(client_id);
}

void P2PServer::send_to_client(const std::string& client_id, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = client_to_socket_.find(client_id);
    if (it != client_to_socket_.end()) {
        std::string msg = message + "\n";
        send(it->second, msg.c_str(), msg.length(), 0);
    }
}

std::vector<std::string> P2PServer::get_cluster_members(const std::string& cluster_id) const {
    std::vector<std::string> members;
    auto it = clusters_.find(cluster_id);
    if (it != clusters_.end() && it->second) {
        for (const auto& member : it->second->members) {
            members.push_back(member);
        }
    }
    return members;
}

void P2PServer::process_message(int client_socket, const std::string& message) {
    using namespace protocol;
    
    MessageType type = Message::parse_type(message);
    std::vector<std::string> params = Message::parse_params(message);
    
    std::string response;
    std::string client_id;
    
    
    if (params.empty()) {
        response = Message::error("Missing client ID");
        response += "\n";
        send(client_socket, response.c_str(), response.length(), 0);
        return;
    }
    
    client_id = params[0];
    
    client_id.erase(0, client_id.find_first_not_of(" \t\n\r"));
    client_id.erase(client_id.find_last_not_of(" \t\n\r") + 1);
    
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        client_to_socket_[client_id] = client_socket;
        
        if (client_to_ip_.find(client_id) == client_to_ip_.end()) {
            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            if (getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len) == 0) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
                client_to_ip_[client_id] = std::string(ip_str);
            }
        }
    }
    
    switch (type) {
        case MessageType::CREATE_CLUSTER: {
            if (params.size() >= 3) {
                int n = std::stoi(params[1]);
                int k = std::stoi(params[2]);
                
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (client_to_cluster_.find(client_id) != client_to_cluster_.end()) {
                        response = Message::error("Client is already in a cluster. Leave the current cluster first.");
                    } else {
                        std::string cluster_id = create_cluster(client_id, n, k);
                        if (!cluster_id.empty()) {
                            response = Message::cluster_created(cluster_id);
                        } else {
                            response = Message::error("Failed to create cluster");
                        }
                    }
                }
            } else {
                response = Message::error("Invalid CREATE_CLUSTER parameters");
            }
            break;
        }
        
        case MessageType::JOIN_CLUSTER: {
            if (params.size() >= 2) {
                std::string cluster_id = params[1];
                if (join_cluster(client_id, cluster_id)) {
                    response = Message::cluster_joined(cluster_id);
                    Cluster* cluster = get_cluster(cluster_id);
                    if (cluster && cluster->is_active) {
                        response += "\n" + Message::cluster_ready(cluster_id);
                    }
                } else {
                    response = Message::error("Failed to join cluster");
                }
            } else {
                response = Message::error("Invalid JOIN_CLUSTER parameters");
            }
            break;
        }
        
        case MessageType::LIST_CLUSTERS: {
            
            auto clusters = list_clusters();
            std::vector<std::string> cluster_data;
            for (const auto& cluster : clusters) {
                std::ostringstream oss;
                oss << cluster.cluster_id << ":" << cluster.creator_id << ":" 
                    << cluster.n << ":" << cluster.k << ":" 
                    << cluster.members.size() << ":" << (cluster.is_active ? "1" : "0");
                cluster_data.push_back(oss.str());
            }
            response = Message::cluster_list(cluster_data);
            break;
        }
        
        case MessageType::LEAVE_CLUSTER: {
            remove_client(client_id);
            response = "OK|Left cluster";
            break;
        }
        
        case MessageType::GET_CLUSTER_MEMBERS: {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = client_to_cluster_.find(client_id);
            if (it != client_to_cluster_.end()) {
                auto members = get_cluster_members(it->second);
                response = Message::cluster_members(members);
            } else {
                response = Message::error("Client not in a cluster");
            }
            break;
        }
        
        case MessageType::REGISTER_P2P_PORT: {
            if (params.size() >= 2) {
                uint16_t p2p_port = static_cast<uint16_t>(std::stoi(params[1]));
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    client_to_p2p_port_[client_id] = p2p_port;
                }
                response = "OK|P2P port registered";
            } else {
                response = Message::error("Invalid REGISTER_P2P_PORT parameters");
            }
            break;
        }
        
        case MessageType::GET_CLIENT_INFO: {
            if (params.size() >= 2) {
                std::string target_client_id = params[1];
                std::lock_guard<std::mutex> lock(mutex_);
                auto ip_it = client_to_ip_.find(target_client_id);
                auto port_it = client_to_p2p_port_.find(target_client_id);
                
                if (ip_it != client_to_ip_.end() && port_it != client_to_p2p_port_.end()) {
                    response = Message::client_info(ip_it->second, port_it->second);
                } else {
                    response = Message::error("Client info not available (client may not have registered P2P port)");
                }
            } else {
                response = Message::error("Invalid GET_CLIENT_INFO parameters");
            }
            break;
        }
        
        default:
            response = Message::error("Unknown message type");
            break;
    }
    if (response.empty()) {
        response = Message::error("Internal server error: empty response");
    }
    
    response += "\n";
    send(client_socket, response.c_str(), response.length(), 0);
}

void P2PServer::handle_client(int client_socket) {
    char buffer[4096];
    std::string client_id = "client_" + std::to_string(client_socket);
    
    
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    if (getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len) == 0) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            client_to_ip_[client_id] = std::string(ip_str);
        }
    }
    
    std::cout << "\033[36m[SERVER]\033[0m Client connected: \033[33m" << client_id << "\033[0m\n";
    
    while (running_) {
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received <= 0) {
            break;
        }
        
        std::string message(buffer, bytes_received);
        
        if (!message.empty() && message.back() == '\n') {
            message.pop_back();
        }
        
        process_message(client_socket, message);
    }
    
    std::cout << "\033[33m[SERVER]\033[0m Client disconnected: \033[33m" << client_id << "\033[0m\n";
    remove_client(client_id);
    close(client_socket);
}

void P2PServer::start() {
    server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_ < 0) {
        std::cerr << "\033[31m[SERVER]\033[0m Error creating socket\n";
        return;
    }
    
    int opt = 1;
    setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_);
    
    if (bind(server_socket_, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "\033[31m[SERVER]\033[0m Error binding to port " << port_ << "\n";
        close(server_socket_);
        return;
    }
    
    if (listen(server_socket_, 10) < 0) {
        std::cerr << "\033[31m[SERVER]\033[0m Error listening\n";
        close(server_socket_);
        return;
    }
    
    running_ = true;
    std::cout << "\033[32m[SERVER]\033[0m Started on port \033[36m" << port_ << "\033[0m\n";
    
    while (running_) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket_, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_socket < 0) {
            continue;
        }
        
        
        std::thread(&P2PServer::handle_client, this, client_socket).detach();
    }
}

void P2PServer::stop() {
    if (running_) {
        running_ = false;
        if (server_socket_ >= 0) {
            close(server_socket_);
            server_socket_ = -1;
        }
        std::cout << "\033[33m[SERVER]\033[0m Stopped\n";
    }
}

} 
} 

