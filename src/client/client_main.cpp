#include "p2p_client.hpp"
#include <iostream>
#include <string>

void print_menu() {
    std::cout << "\n=== P2P Client Menu ===\n";
    std::cout << "1. Create cluster (n, k)\n";
    std::cout << "2. List available clusters\n";
    std::cout << "3. Join cluster\n";
    std::cout << "4. Show my cluster status\n";
    std::cout << "5. Leave current cluster\n";
    std::cout << "6. Send message to cluster member\n";
    std::cout << "7. Check for messages\n";
    std::cout << "8. Exit\n";
    std::cout << "Choice: ";
}

void print_clusters(const std::vector<vmdt::p2p::ClusterInfo>& clusters) {
    if (clusters.empty()) {
        std::cout << "No clusters available.\n";
        return;
    }
    
    std::cout << "\n=== Available Clusters ===\n";
    std::cout << "ID\t\tCreator\t\tn\tk\tMembers\tStatus\n";
    std::cout << "--------------------------------------------------------\n";
    
    for (const auto& cluster : clusters) {
        std::cout << cluster.cluster_id << "\t"
                  << cluster.creator_id << "\t"
                  << cluster.n << "\t"
                  << cluster.k << "\t"
                  << cluster.current_members << "/" << cluster.n << "\t"
                  << (cluster.is_active ? "READY" : "WAITING") << "\n";
    }
}

int main(int argc, char* argv[]) {
    std::string server_host = "127.0.0.1";
    uint16_t server_port = 8080;
    
    if (argc > 1) {
        server_host = argv[1];
    }
    if (argc > 2) {
        server_port = static_cast<uint16_t>(std::stoi(argv[2]));
    }
    
    std::cout << "=== P2P Client ===\n";
    std::cout << "Connecting to server at " << server_host << ":" << server_port << "\n";
    
    vmdt::p2p::P2PClient client(server_host, server_port);
    
    if (!client.connect()) {
        std::cerr << "Failed to connect to server. Exiting.\n";
        return 1;
    }
    
    bool running = true;
    std::string input;
    
    while (running) {
        
        client.check_for_messages();
        
        print_menu();
        std::getline(std::cin, input);
        
        if (input.empty()) {
            continue;
        }
        
        int choice = std::stoi(input);
        
        switch (choice) {
            case 1: {
                std::cout << "Enter n (total shares): ";
                std::getline(std::cin, input);
                int n = std::stoi(input);
                
                std::cout << "Enter k (threshold): ";
                std::getline(std::cin, input);
                int k = std::stoi(input);
                
                if (n < k || k < 2 || n < 2) {
                    std::cerr << "Invalid parameters: n >= k >= 2 required\n";
                    break;
                }
                
                if (client.is_in_cluster()) {
                    std::cerr << "You are already in a cluster (" << client.get_my_cluster_id() 
                              << "). Please leave it first (option 5).\n";
                    break;
                }
                
                std::string cluster_id = client.create_cluster(n, k);
                if (!cluster_id.empty()) {
                    std::cout << "Successfully created cluster: " << cluster_id << "\n";
                    std::cout << "Waiting for " << (n - 1) << " more members to join...\n";
                } else {
                    std::cerr << "Failed to create cluster\n";
                }
                break;
            }
            
            case 2: {
                auto clusters = client.list_clusters();
                print_clusters(clusters);
                break;
            }
            
            case 3: {
                std::cout << "Enter cluster ID to join: ";
                std::getline(std::cin, input);
                
                if (client.join_cluster(input)) {
                    std::cout << "Successfully joined cluster: " << input << "\n";
                    if (client.is_cluster_ready()) {
                        std::cout << "Cluster is ready! Communication can start.\n";
                    }
                } else {
                    std::cerr << "Failed to join cluster\n";
                }
                break;
            }
            
            case 4: {
                if (client.is_in_cluster()) {
                    std::cout << "Current cluster: " << client.get_my_cluster_id() << "\n";
                    
                    bool ready = client.is_cluster_ready();
                    std::cout << "Status: " << (ready ? "READY" : "WAITING") << "\n";
                    std::cout << "Parameters: n=" << client.get_cluster_n() << ", k=" << client.get_cluster_k() << "\n";
                    
                    auto members = client.get_cluster_members();
                    std::cout << "Cluster members (" << members.size() << "): ";
                    for (size_t i = 0; i < members.size(); ++i) {
                        std::cout << members[i];
                        if (i < members.size() - 1) std::cout << ", ";
                    }
                    std::cout << "\n";
                } else {
                    std::cout << "Not in any cluster\n";
                }
                break;
            }
            
            case 5: {
                if (client.leave_cluster()) {
                    std::cout << "Successfully left cluster\n";
                } else {
                    std::cerr << "Failed to leave cluster or not in a cluster\n";
                }
                break;
            }
            
            case 6: {
                if (!client.is_cluster_ready()) {
                    std::cerr << "Cluster is not ready yet. Wait for all members to join.\n";
                    break;
                }
                
                auto members = client.get_cluster_members();
                if (members.size() < 2) {
                    std::cerr << "Not enough members in cluster to send messages\n";
                    break;
                }
                
                std::cout << "Available members:\n";
                for (size_t i = 0; i < members.size(); ++i) {
                    std::cout << "  " << (i+1) << ". " << members[i] << "\n";
                }
                
                std::cout << "Enter target client ID: ";
                std::getline(std::cin, input);
                std::string target_id = input;
                
                std::cout << "Enter message to send: ";
                std::getline(std::cin, input);
                std::string message = input;
                
                if (client.send_message(target_id, message)) {
                    std::cout << "Message sent successfully!\n";
                } else {
                    std::cerr << "Failed to send message\n";
                }
                break;
            }
            
            case 7: {
                std::cout << "\n[CLIENT] Checking for incoming messages...\n";
                client.check_for_messages();
                std::cout << "[CLIENT] Message check complete. Press Enter to continue...\n";
                std::cin.ignore();
                break;
            }
            
            case 8: {
                running = false;
                break;
            }
            
            default:
                std::cout << "Invalid choice\n";
                break;
        }
    }
    
    client.disconnect();
    std::cout << "Goodbye!\n";
    return 0;
}

