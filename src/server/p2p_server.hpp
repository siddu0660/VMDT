#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <memory>
#include <cstdint>

namespace vmdt {
namespace p2p {

struct Cluster {
    std::string cluster_id;
    std::string creator_id;
    int n;  
    int k;  
    std::set<std::string> members;  
    bool is_active;  
    
    Cluster(const std::string& id, const std::string& creator, int n_val, int k_val)
        : cluster_id(id), creator_id(creator), n(n_val), k(k_val), is_active(false) {}
};

class P2PServer {
public:
    P2PServer(uint16_t port);
    ~P2PServer();
    
    void start();
    void stop();
    
    
    std::string create_cluster(const std::string& client_id, int n, int k);
    bool join_cluster(const std::string& client_id, const std::string& cluster_id);
    std::vector<Cluster> list_clusters() const;
    Cluster* get_cluster(const std::string& cluster_id);
    void remove_client(const std::string& client_id);
    
private:
    uint16_t port_;
    int server_socket_;
    bool running_;
    mutable std::mutex mutex_;
    
    std::map<std::string, std::unique_ptr<Cluster>> clusters_;
    std::map<std::string, std::string> client_to_cluster_;  
    std::map<std::string, int> client_to_socket_;  
    std::map<std::string, std::string> client_to_ip_;  
    std::map<std::string, uint16_t> client_to_p2p_port_;  
    
    void handle_client(int client_socket);
    void process_message(int client_socket, const std::string& message);
    std::string generate_cluster_id();
    void check_cluster_ready(const std::string& cluster_id);
    void send_to_client(const std::string& client_id, const std::string& message);
    std::vector<std::string> get_cluster_members(const std::string& cluster_id) const;
};

} 
} 

