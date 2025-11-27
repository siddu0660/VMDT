#pragma once

#include <vmdt/consensus.hpp>
#include <queue>
#include <condition_variable>
#include <thread>
#include <set>


namespace vmdt
{
    namespace consensus
    {
        class RaftNode
        {
        public:
            RaftNode(
                NodeId node_id,
                std::vector<NodeId> cluster_nodes,
                std::shared_ptr<NetworkInterface> network);

            ~RaftNode();

            void start();
            void stop();

            bool submit_log_entry(const SessionIntent &intent);
            std::vector<SessionIntent> read_log();
            bool is_leader() const;
            NodeId current_leader() const;

            RequestVoteResponse handle_request_vote(const RequestVoteRequest &req);
            AppendEntriesResponse handle_append_entries(const AppendEntriesRequest &req);

        private:
            std::unique_ptr<ConsensusState> state_;
            std::shared_ptr<NetworkInterface> network_;
            NodeId node_id_;
            std::vector<NodeId> cluster_nodes_;

            std::atomic<bool> running_;
            std::thread raft_thread_;
            std::mutex mutex_;
            std::condition_variable cv_;

            static constexpr int MIN_ELECTION_TIMEOUT_MS = 150;
            static constexpr int MAX_ELECTION_TIMEOUT_MS = 300;
            static constexpr int HEARTBEAT_INTERVAL_MS = 50;

            std::chrono::time_point<std::chrono::steady_clock> election_deadline_;
            void reset_election_timer();
            bool is_election_timeout() const;

            struct ReplicationState
            {
                LogIndex next_index;
                LogIndex match_index;
                std::chrono::time_point<std::chrono::steady_clock> last_response;
            };
            std::map<NodeId, ReplicationState> replication_state_;

            void raft_main_loop();

            void run_as_follower();
            void run_as_candidate();
            void run_as_leader();

            void start_election();
            void send_vote_requests();
            void process_vote_response(NodeId from, const RequestVoteResponse &resp);

            void send_append_entries_to_all();
            void send_append_entries_to(NodeId target);
            void process_append_entries_response(
                NodeId from,
                const AppendEntriesResponse &resp,
                LogIndex sent_prev_log_index);

            void advance_commit_index();
            void apply_committed_entries();

            bool append_entries_from_leader(const AppendEntriesRequest &req);

            LogIndex majority_match_index() const;
            size_t count_matching_nodes(LogIndex index) const;
        };

        class RaftCluster
        {
        public:
            RaftCluster(size_t num_nodes);
            ~RaftCluster();

            void add_node(std::shared_ptr<RaftNode> node);

            std::vector<std::shared_ptr<RaftNode>> get_nodes() const;
            std::shared_ptr<RaftNode> get_leader() const;

            bool submit_intent(const SessionIntent &intent);

            std::vector<SessionIntent> read_committed_log() const;

            void start_all();
            void stop_all();

            bool wait_for_leader(std::chrono::milliseconds timeout);

        private:
            std::vector<std::shared_ptr<RaftNode>> nodes_;
            mutable std::mutex mutex_;
        };

        
        
        
        

        

        
        

        
        
        
        

        
        
        
        

        
        
        
        

        
        
        

        
        
        

        
        
        

        std::shared_ptr<RaftCluster> create_test_cluster(size_t num_nodes);

        std::vector<uint8_t> serialize_request_vote(const RequestVoteRequest &req);
        RequestVoteRequest deserialize_request_vote(const std::vector<uint8_t> &data);

        std::vector<uint8_t> serialize_append_entries(const AppendEntriesRequest &req);
        AppendEntriesRequest deserialize_append_entries(const std::vector<uint8_t> &data);

    }
}