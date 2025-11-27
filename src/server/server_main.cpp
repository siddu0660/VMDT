#include "p2p_server.hpp"
#include <iostream>
#include <csignal>
#include <atomic>
#include <thread>
#include <chrono>

std::atomic<bool> g_running{true};
vmdt::p2p::P2PServer* g_server = nullptr;

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\n[SERVER] Shutting down...\n";
        g_running = false;
        if (g_server) {
            g_server->stop();
        }
    }
}

int main(int argc, char* argv[]) {
    uint16_t port = 8080;
    
    if (argc > 1) {
        port = static_cast<uint16_t>(std::stoi(argv[1]));
    }
    
    std::cout << "=== P2P Cluster Server ===\n";
    std::cout << "Starting server on port " << port << "\n";
    std::cout << "Press Ctrl+C to stop\n\n";
    
    vmdt::p2p::P2PServer server(port);
    g_server = &server;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    
    std::thread server_thread([&server]() {
        server.start();
    });
    
    
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    server.stop();
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    return 0;
}

