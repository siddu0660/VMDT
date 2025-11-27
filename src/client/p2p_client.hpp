#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace vmdt {
namespace p2p {

struct ClusterInfo {
    std::string cluster_id;
    std::string creator_id;
    int n;
    int k;
    int current_members;
    bool is_active;
};

class P2PClient {
public:
    P2PClient(const std::string& server_host, uint16_t server_port);
    ~P2PClient();
    
    bool connect();
    void disconnect();
    
    
    std::string create_cluster(int n, int k);
    bool join_cluster(const std::string& cluster_id);
    bool leave_cluster();
    std::vector<ClusterInfo> list_clusters();
    std::vector<std::string> get_cluster_members();
    std::string get_my_cluster_id() const { return my_cluster_id_; }
    bool is_in_cluster() const { return !my_cluster_id_.empty(); }
    bool is_cluster_ready();
    int get_cluster_n() const { return cluster_n_; }
    int get_cluster_k() const { return cluster_k_; }
    
    
    bool send_message(const std::string& target_client_id, const std::string& message);
    bool send_file(const std::string& target_client_id, const std::string& filepath);
    void check_for_messages();  
    bool reconstruct_from_files(const std::string& base_filename, const std::string& output_filename);  
    
    
    void send_message_to_server(const std::string& message);
    std::string receive_message_from_server();
    
private:
    std::string server_host_;
    uint16_t server_port_;
    int socket_fd_;
    bool connected_;
    std::string client_id_;
    std::string my_cluster_id_;
    bool cluster_ready_;
    int cluster_n_;
    int cluster_k_;
    
    
    int p2p_listen_socket_;
    uint16_t p2p_port_;
    bool p2p_listening_;
    
    
    std::map<std::string, std::map<int, std::vector<uint8_t>>> pending_shares_;  
    std::map<std::string, int> message_share_counts_;
    std::map<std::string, std::pair<bool, std::string>> pending_file_metadata_;  
    
    
    enum class ShareState {
        ACTIVE,    
        FROZEN,    
        CLAIMED    
    };
    
    struct SharePoolEntry {
        std::string sender_id;
        std::string receiver_id;
        std::map<int, std::pair<ShareState, std::string>> shares;  
        int active_count;
        int frozen_count;
        int claimed_count;
        bool is_file;
        std::string filename;
    };
    
    std::map<std::string, SharePoolEntry> share_pool_;  
    
    std::string generate_client_id();
    std::string send_request(const std::string& request);
    std::string base64_encode(const std::vector<uint8_t>& data);
    std::vector<uint8_t> base64_decode(const std::string& encoded);
    void handle_message_share(const std::string& message);
    void reconstruct_message(const std::string& message_id);
    
    
    bool start_p2p_listener();
    void stop_p2p_listener();
    bool send_share_to_peer(const std::string& peer_ip, uint16_t peer_port, 
                           const std::string& from_client, const std::string& to_client,
                           const std::string& target_client, int share_index, 
                           const std::string& encoded_share);
    std::pair<std::string, uint16_t> get_client_info(const std::string& target_client_id);
    void process_p2p_connections();
    
    
    bool broadcast_share_pool_add(const std::string& message_id, const std::string& sender_id,
                                  const std::string& receiver_id, 
                                  const std::vector<std::pair<int, std::string>>& all_shares,
                                  int k_threshold, bool is_file = false, const std::string& filename = "");
    void handle_share_pool_add(const std::string& message);
    void handle_share_pool_claim(const std::string& message);
    void handle_share_pool_ack(const std::string& message);
    void handle_share_pool_unfreeze(const std::string& message);
    void handle_share_pool_remove(const std::string& message);
    bool claim_share_from_pool(const std::string& message_id, int share_index);
    void send_ack_to_sender(const std::string& message_id);
    bool send_to_all_cluster_members(const std::string& message);
};

} 
} 

