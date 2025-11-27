#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <mutex>
#include <atomic>
#include <map>
#include <chrono>
#include <thread>
#include <functional>

namespace vmdt
{
    namespace consensus
    {
        using NodeId = std::string;
        using Term = uint64_t;
        using LogIndex = uint64_t;

        struct SessionIntent
        {
            std::string session_id;
            std::string sender_id;
            std::string receiver_id;
            std::vector<uint8_t> encrypted_key; 
            uint64_t timestamp;
            std::vector<uint8_t> signature; 

            std::vector<uint8_t> serialize() const;
            static SessionIntent deserialize(const std::vector<uint8_t> &data);
        };

        struct LogEntry
        {
            Term term;
            LogIndex index;
            SessionIntent intent;

            std::vector<uint8_t> serialize() const;
            static LogEntry deserialize(const std::vector<uint8_t> &data);
        };

        enum class NodeState
        {
            FOLLOWER,
            CANDIDATE,
            LEADER
        };

        struct RequestVoteRequest
        {
            Term term;
            NodeId candidate_id;
            LogIndex last_log_index;
            Term last_log_term;

            std::vector<uint8_t> serialize() const;
            static RequestVoteRequest deserialize(const std::vector<uint8_t> &data);
        };

        struct RequestVoteResponse
        {
            Term term;
            bool vote_granted;

            std::vector<uint8_t> serialize() const;
            static RequestVoteResponse deserialize(const std::vector<uint8_t> &data);
        };

        struct AppendEntriesRequest
        {
            Term term;
            NodeId leader_id;
            LogIndex prev_log_index;
            Term prev_log_term;
            std::vector<LogEntry> entries;
            LogIndex leader_commit;

            std::vector<uint8_t> serialize() const;
            static AppendEntriesRequest deserialize(const std::vector<uint8_t> &data);
        };

        struct AppendEntriesResponse
        {
            Term term;
            bool success;
            LogIndex match_index;

            std::vector<uint8_t> serialize() const;
            static AppendEntriesResponse deserialize(const std::vector<uint8_t> &data);
        };

        class ConsensusState
        {
        public:
            ConsensusState(NodeId node_id, std::vector<NodeId> cluster_nodes);

            NodeState get_state() const { return state_; }
            Term get_current_term() const { return current_term_; }
            NodeId get_voted_for() const { return voted_for_; }
            NodeId get_leader_id() const { return leader_id_; }

            void append_entry(const LogEntry &entry);
            LogEntry get_entry(LogIndex index) const;
            LogIndex get_last_log_index() const;
            Term get_last_log_term() const;
            std::vector<LogEntry> get_entries_from(LogIndex start) const;
            size_t log_size() const { return log_.size(); }

            void set_commit_index(LogIndex index);
            LogIndex get_commit_index() const;
            std::vector<SessionIntent> get_committed_sessions() const;

            void become_follower(Term term);
            void become_candidate();
            void become_leader();

            bool request_vote(const RequestVoteRequest &req);
            void record_vote(NodeId node_id);
            bool has_majority_votes(size_t cluster_size) const;

        private:
            mutable std::mutex mutex_;

            
            Term current_term_;
            NodeId voted_for_;
            std::vector<LogEntry> log_;

            
            LogIndex commit_index_;
            LogIndex last_applied_;

            
            NodeId node_id_;
            NodeState state_;
            NodeId leader_id_;

            std::map<NodeId, bool> votes_received_;
            std::vector<NodeId> cluster_nodes_;
        };

        class ConsensusCoordinator
        {
        public:
            ConsensusCoordinator(
                NodeId node_id,
                std::vector<NodeId> cluster_nodes,
                int k_threshold,
                int n_total_shares);

            ~ConsensusCoordinator();

            bool propose_session(const SessionIntent &intent);
            std::vector<SessionIntent> read_committed_sessions();
            SessionIntent get_session(const std::string &session_id);

            
            void start();
            void stop();
            bool is_leader() const;
            NodeId get_leader_id() const;

            struct ShareAssignment
            {
                std::string session_id;
                std::map<NodeId, int> node_to_share_index;
            };

            ShareAssignment assign_shares_to_nodes(const std::string &session_id);

        private:
            
            std::unique_ptr<ConsensusState> state_;
            NodeId node_id_;
            std::vector<NodeId> cluster_nodes_;
            int k_threshold_;
            int n_total_shares_;

            
            std::atomic<bool> running_;
            std::thread election_thread_;
            std::thread heartbeat_thread_;

            
            std::chrono::milliseconds election_timeout_;
            std::chrono::milliseconds heartbeat_interval_;
            std::chrono::time_point<std::chrono::steady_clock> last_heartbeat_;

            
            struct FollowerState
            {
                LogIndex next_index;
                LogIndex match_index;
            };
            std::map<NodeId, FollowerState> follower_states_;

            void election_timer_loop();
            void heartbeat_loop();
            void start_election();
            void send_heartbeats();

            bool replicate_log_entry(const LogEntry &entry);
            void update_commit_index();

            void reset_election_timer();
            bool election_timeout_elapsed() const;
        };

        
        
        

        class NetworkInterface
        {
        public:
            virtual ~NetworkInterface() = default;

            virtual bool send_request_vote(const NodeId &target, const RequestVoteRequest &req) = 0;
            virtual bool send_append_entries(const NodeId &target, const AppendEntriesRequest &req) = 0;

            virtual void on_request_vote_received(
                const NodeId &from,
                const RequestVoteRequest &req,
                std::function<void(RequestVoteResponse)> respond) = 0;

            virtual void on_append_entries_received(
                const NodeId &from,
                const AppendEntriesRequest &req,
                std::function<void(AppendEntriesResponse)> respond) = 0;
        };

        class ShareDistributionManager
        {
        public:
            ShareDistributionManager(int k_threshold, int n_total_shares);

            struct ShareMapping
            {
                std::map<NodeId, std::vector<uint8_t>> node_shares; 
                std::map<NodeId, int> node_share_indices;           
            };

            ShareMapping distribute_shares(
                const std::vector<uint8_t> &data,
                const std::vector<NodeId> &nodes);

            std::vector<uint8_t> reconstruct_from_shares(
                const std::map<NodeId, std::vector<uint8_t>> &node_shares);

            bool has_sufficient_shares(size_t available_shares) const
            {
                return available_shares >= static_cast<size_t>(k_threshold_);
            }

        private:
            int k_threshold_;
            int n_total_shares_;
        };

        std::chrono::milliseconds generate_election_timeout();

        NodeId generate_node_id();

        std::string generate_session_id();

    }
}