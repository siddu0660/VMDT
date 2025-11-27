#include <vmdt/consensus.hpp>
#include <vmdt/ssms.hpp>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <thread>
#include <functional>
#include <set>

namespace vmdt
{
    namespace consensus
    {
        static void write_uint64(std::vector<uint8_t> &buffer, uint64_t value)
        {
            buffer.push_back((value >> 56) & 0xFF);
            buffer.push_back((value >> 48) & 0xFF);
            buffer.push_back((value >> 40) & 0xFF);
            buffer.push_back((value >> 32) & 0xFF);
            buffer.push_back((value >> 24) & 0xFF);
            buffer.push_back((value >> 16) & 0xFF);
            buffer.push_back((value >> 8) & 0xFF);
            buffer.push_back(value & 0xFF);
        }

        static uint64_t read_uint64(const std::vector<uint8_t> &buffer, size_t &offset)
        {
            if (offset + 8 > buffer.size())
                throw std::runtime_error("Buffer underflow reading uint64");

            uint64_t value = ((uint64_t)buffer[offset] << 56) |
                             ((uint64_t)buffer[offset + 1] << 48) |
                             ((uint64_t)buffer[offset + 2] << 40) |
                             ((uint64_t)buffer[offset + 3] << 32) |
                             ((uint64_t)buffer[offset + 4] << 24) |
                             ((uint64_t)buffer[offset + 5] << 16) |
                             ((uint64_t)buffer[offset + 6] << 8) |
                             ((uint64_t)buffer[offset + 7]);
            offset += 8;
            return value;
        }

        static void write_string(std::vector<uint8_t> &buffer, const std::string &str)
        {
            uint64_t len = str.size();
            write_uint64(buffer, len);
            buffer.insert(buffer.end(), str.begin(), str.end());
        }

        static std::string read_string(const std::vector<uint8_t> &buffer, size_t &offset)
        {
            uint64_t len = read_uint64(buffer, offset);
            if (offset + len > buffer.size())
                throw std::runtime_error("Buffer underflow reading string");

            std::string str(buffer.begin() + offset, buffer.begin() + offset + len);
            offset += len;
            return str;
        }

        static void write_bytes(std::vector<uint8_t> &buffer, const std::vector<uint8_t> &data)
        {
            uint64_t len = data.size();
            write_uint64(buffer, len);
            buffer.insert(buffer.end(), data.begin(), data.end());
        }

        static std::vector<uint8_t> read_bytes(const std::vector<uint8_t> &buffer, size_t &offset)
        {
            uint64_t len = read_uint64(buffer, offset);
            if (offset + len > buffer.size())
                throw std::runtime_error("Buffer underflow reading bytes");

            std::vector<uint8_t> data(buffer.begin() + offset, buffer.begin() + offset + len);
            offset += len;
            return data;
        }

        std::vector<uint8_t> SessionIntent::serialize() const
        {
            std::vector<uint8_t> buffer;
            write_string(buffer, session_id);
            write_string(buffer, sender_id);
            write_string(buffer, receiver_id);
            write_bytes(buffer, encrypted_key);
            write_uint64(buffer, timestamp);
            write_bytes(buffer, signature);
            return buffer;
        }

        SessionIntent SessionIntent::deserialize(const std::vector<uint8_t> &data)
        {
            SessionIntent intent;
            size_t offset = 0;
            intent.session_id = read_string(data, offset);
            intent.sender_id = read_string(data, offset);
            intent.receiver_id = read_string(data, offset);
            intent.encrypted_key = read_bytes(data, offset);
            intent.timestamp = read_uint64(data, offset);
            intent.signature = read_bytes(data, offset);
            return intent;
        }

        std::vector<uint8_t> LogEntry::serialize() const
        {
            std::vector<uint8_t> buffer;
            write_uint64(buffer, term);
            write_uint64(buffer, index);
            auto intent_data = intent.serialize();
            write_bytes(buffer, intent_data);
            return buffer;
        }

        LogEntry LogEntry::deserialize(const std::vector<uint8_t> &data)
        {
            LogEntry entry;
            size_t offset = 0;
            entry.term = read_uint64(data, offset);
            entry.index = read_uint64(data, offset);
            auto intent_data = read_bytes(data, offset);
            entry.intent = SessionIntent::deserialize(intent_data);
            return entry;
        }

        std::vector<uint8_t> RequestVoteRequest::serialize() const
        {
            std::vector<uint8_t> buffer;
            write_uint64(buffer, term);
            write_string(buffer, candidate_id);
            write_uint64(buffer, last_log_index);
            write_uint64(buffer, last_log_term);
            return buffer;
        }

        RequestVoteRequest RequestVoteRequest::deserialize(const std::vector<uint8_t> &data)
        {
            RequestVoteRequest req;
            size_t offset = 0;
            req.term = read_uint64(data, offset);
            req.candidate_id = read_string(data, offset);
            req.last_log_index = read_uint64(data, offset);
            req.last_log_term = read_uint64(data, offset);
            return req;
        }

        std::vector<uint8_t> RequestVoteResponse::serialize() const
        {
            std::vector<uint8_t> buffer;
            write_uint64(buffer, term);
            buffer.push_back(vote_granted ? 1 : 0);
            return buffer;
        }

        RequestVoteResponse RequestVoteResponse::deserialize(const std::vector<uint8_t> &data)
        {
            RequestVoteResponse resp;
            size_t offset = 0;
            resp.term = read_uint64(data, offset);
            if (offset >= data.size())
                throw std::runtime_error("Buffer underflow reading vote_granted");
            resp.vote_granted = data[offset] != 0;
            return resp;
        }

        std::vector<uint8_t> AppendEntriesRequest::serialize() const
        {
            std::vector<uint8_t> buffer;
            write_uint64(buffer, term);
            write_string(buffer, leader_id);
            write_uint64(buffer, prev_log_index);
            write_uint64(buffer, prev_log_term);
            write_uint64(buffer, leader_commit);

            
            write_uint64(buffer, entries.size());
            for (const auto &entry : entries)
            {
                auto entry_data = entry.serialize();
                write_bytes(buffer, entry_data);
            }

            return buffer;
        }

        AppendEntriesRequest AppendEntriesRequest::deserialize(const std::vector<uint8_t> &data)
        {
            AppendEntriesRequest req;
            size_t offset = 0;
            req.term = read_uint64(data, offset);
            req.leader_id = read_string(data, offset);
            req.prev_log_index = read_uint64(data, offset);
            req.prev_log_term = read_uint64(data, offset);
            req.leader_commit = read_uint64(data, offset);

            uint64_t num_entries = read_uint64(data, offset);
            for (uint64_t i = 0; i < num_entries; i++)
            {
                auto entry_data = read_bytes(data, offset);
                req.entries.push_back(LogEntry::deserialize(entry_data));
            }

            return req;
        }

        std::vector<uint8_t> AppendEntriesResponse::serialize() const
        {
            std::vector<uint8_t> buffer;
            write_uint64(buffer, term);
            buffer.push_back(success ? 1 : 0);
            write_uint64(buffer, match_index);
            return buffer;
        }

        AppendEntriesResponse AppendEntriesResponse::deserialize(const std::vector<uint8_t> &data)
        {
            AppendEntriesResponse resp;
            size_t offset = 0;
            resp.term = read_uint64(data, offset);
            if (offset >= data.size())
                throw std::runtime_error("Buffer underflow reading success");
            resp.success = data[offset++] != 0;
            resp.match_index = read_uint64(data, offset);
            return resp;
        }

        ConsensusState::ConsensusState(NodeId node_id, std::vector<NodeId> cluster_nodes)
            : current_term_(0),
              voted_for_(""),
              commit_index_(0),
              last_applied_(0),
              node_id_(node_id),
              state_(NodeState::FOLLOWER),
              leader_id_(""),
              cluster_nodes_(cluster_nodes)
        {
        }

        void ConsensusState::append_entry(const LogEntry &entry)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            log_.push_back(entry);
        }

        LogEntry ConsensusState::get_entry(LogIndex index) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (index == 0 || index > log_.size())
            {
                throw std::out_of_range("Invalid log index");
            }
            return log_[index - 1]; 
        }

        LogIndex ConsensusState::get_last_log_index() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return log_.size();
        }

        Term ConsensusState::get_last_log_term() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (log_.empty())
                return 0;
            return log_.back().term;
        }

        std::vector<LogEntry> ConsensusState::get_entries_from(LogIndex start) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (start > log_.size())
                return {};
            return std::vector<LogEntry>(log_.begin() + start, log_.end());
        }

        void ConsensusState::set_commit_index(LogIndex index)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            commit_index_ = std::min(index, static_cast<LogIndex>(log_.size()));
        }

        LogIndex ConsensusState::get_commit_index() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return commit_index_;
        }

        std::vector<SessionIntent> ConsensusState::get_committed_sessions() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<SessionIntent> sessions;
            for (size_t i = 0; i < commit_index_ && i < log_.size(); i++)
            {
                sessions.push_back(log_[i].intent);
            }
            return sessions;
        }

        void ConsensusState::become_follower(Term term)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            state_ = NodeState::FOLLOWER;
            current_term_ = term;
            voted_for_ = "";
            leader_id_ = "";
            votes_received_.clear();
        }

        void ConsensusState::become_candidate()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            state_ = NodeState::CANDIDATE;
            current_term_++;
            voted_for_ = node_id_;
            leader_id_ = "";
            votes_received_.clear();
            votes_received_[node_id_] = true; 
        }

        void ConsensusState::become_leader()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            state_ = NodeState::LEADER;
            leader_id_ = node_id_;
            votes_received_.clear();
        }

        bool ConsensusState::request_vote(const RequestVoteRequest &req)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            
            if (req.term < current_term_)
            {
                return false;
            }

            
            if (req.term > current_term_)
            {
                current_term_ = req.term;
                voted_for_ = "";
                state_ = NodeState::FOLLOWER;
            }

            
            if (!voted_for_.empty() && voted_for_ != req.candidate_id)
            {
                return false;
            }

            
            Term last_term = log_.empty() ? 0 : log_.back().term;
            LogIndex last_index = log_.size();

            bool log_ok = (req.last_log_term > last_term) ||
                          (req.last_log_term == last_term && req.last_log_index >= last_index);

            if (log_ok)
            {
                voted_for_ = req.candidate_id;
                return true;
            }

            return false;
        }

        void ConsensusState::record_vote(NodeId node_id)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            votes_received_[node_id] = true;
        }

        bool ConsensusState::has_majority_votes(size_t cluster_size) const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            size_t votes = votes_received_.size();
            return votes > (cluster_size / 2);
        }

        ConsensusCoordinator::ConsensusCoordinator(
            NodeId node_id,
            std::vector<NodeId> cluster_nodes,
            int k_threshold,
            int n_total_shares)
            : state_(std::make_unique<ConsensusState>(node_id, cluster_nodes)),
              node_id_(node_id),
              cluster_nodes_(cluster_nodes),
              k_threshold_(k_threshold),
              n_total_shares_(n_total_shares),
              running_(false),
              election_timeout_(generate_election_timeout()),
              heartbeat_interval_(50), 
              last_heartbeat_(std::chrono::steady_clock::now())
        {
        }

        ConsensusCoordinator::~ConsensusCoordinator()
        {
            stop();
        }

        void ConsensusCoordinator::start()
        {
            running_ = true;
            election_thread_ = std::thread(&ConsensusCoordinator::election_timer_loop, this);
            heartbeat_thread_ = std::thread(&ConsensusCoordinator::heartbeat_loop, this);
        }

        void ConsensusCoordinator::stop()
        {
            running_ = false;
            if (election_thread_.joinable())
                election_thread_.join();
            if (heartbeat_thread_.joinable())
                heartbeat_thread_.join();
        }

        bool ConsensusCoordinator::is_leader() const
        {
            return state_->get_state() == NodeState::LEADER;
        }

        NodeId ConsensusCoordinator::get_leader_id() const
        {
            return state_->get_leader_id();
        }

        bool ConsensusCoordinator::propose_session(const SessionIntent &intent)
        {
            if (!is_leader())
            {
                return false; 
            }

            LogEntry entry;
            entry.term = state_->get_current_term();
            entry.index = state_->get_last_log_index() + 1;
            entry.intent = intent;

            return replicate_log_entry(entry);
        }

        std::vector<SessionIntent> ConsensusCoordinator::read_committed_sessions()
        {
            return state_->get_committed_sessions();
        }

        SessionIntent ConsensusCoordinator::get_session(const std::string &session_id)
        {
            auto sessions = state_->get_committed_sessions();
            for (const auto &session : sessions)
            {
                if (session.session_id == session_id)
                {
                    return session;
                }
            }
            throw std::runtime_error("Session not found: " + session_id);
        }

        ConsensusCoordinator::ShareAssignment ConsensusCoordinator::assign_shares_to_nodes(
            const std::string &session_id)
        {
            ShareAssignment assignment;
            assignment.session_id = session_id;

            
            for (size_t i = 0; i < cluster_nodes_.size() && i < static_cast<size_t>(n_total_shares_); i++)
            {
                assignment.node_to_share_index[cluster_nodes_[i]] = i + 1; 
            }

            return assignment;
        }

        void ConsensusCoordinator::election_timer_loop()
        {
            while (running_)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));

                if (state_->get_state() != NodeState::LEADER && election_timeout_elapsed())
                {
                    start_election();
                }
            }
        }

        void ConsensusCoordinator::heartbeat_loop()
        {
            while (running_)
            {
                std::this_thread::sleep_for(heartbeat_interval_);

                if (state_->get_state() == NodeState::LEADER)
                {
                    send_heartbeats();
                }
            }
        }

        void ConsensusCoordinator::start_election()
        {
            state_->become_candidate();
            reset_election_timer();

            
            
            
        }

        void ConsensusCoordinator::send_heartbeats()
        {
            
            
            
            last_heartbeat_ = std::chrono::steady_clock::now();
        }

        bool ConsensusCoordinator::replicate_log_entry(const LogEntry &entry)
        {
            state_->append_entry(entry);

            
            
            if (is_leader())
            {
                update_commit_index();
                return true;
            }

            return false;
        }

        void ConsensusCoordinator::update_commit_index()
        {
            
            
            if (is_leader())
            {
                state_->set_commit_index(state_->get_last_log_index());
            }
        }

        void ConsensusCoordinator::reset_election_timer()
        {
            last_heartbeat_ = std::chrono::steady_clock::now();
            election_timeout_ = generate_election_timeout();
        }

        bool ConsensusCoordinator::election_timeout_elapsed() const
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - last_heartbeat_);
            return elapsed >= election_timeout_;
        }

        ShareDistributionManager::ShareDistributionManager(int k_threshold, int n_total_shares)
            : k_threshold_(k_threshold), n_total_shares_(n_total_shares)
        {
        }

        ShareDistributionManager::ShareMapping ShareDistributionManager::distribute_shares(
            const std::vector<uint8_t> &data,
            const std::vector<NodeId> &nodes)
        {
            if (nodes.size() < static_cast<size_t>(n_total_shares_))
            {
                throw std::runtime_error("Not enough nodes for share distribution");
            }

            
            auto shares = crypto::SSMS::split_simple(data, k_threshold_, n_total_shares_);

            ShareMapping mapping;
            for (size_t i = 0; i < shares.size() && i < nodes.size(); i++)
            {
                mapping.node_shares[nodes[i]] = shares[i];
                mapping.node_share_indices[nodes[i]] = i + 1; 
            }

            return mapping;
        }

        std::vector<uint8_t> ShareDistributionManager::reconstruct_from_shares(
            const std::map<NodeId, std::vector<uint8_t>> &node_shares)
        {
            if (!has_sufficient_shares(node_shares.size()))
            {
                throw std::runtime_error("Insufficient shares for reconstruction");
            }

            
            std::vector<std::vector<uint8_t>> shares;
            for (const auto &[node_id, share_data] : node_shares)
            {
                shares.push_back(share_data);
            }

            
            return crypto::SSMS::reconstruct_simple(shares);
        }

        std::chrono::milliseconds generate_election_timeout()
        {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dist(150, 300);
            return std::chrono::milliseconds(dist(gen));
        }

        NodeId generate_node_id()
        {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dist(0, 15);

            std::stringstream ss;
            ss << "node_";
            for (int i = 0; i < 8; i++)
            {
                ss << std::hex << dist(gen);
            }
            return ss.str();
        }

        std::string generate_session_id()
        {
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dist(0, 15);

            std::stringstream ss;
            ss << "session_";
            for (int i = 0; i < 16; i++)
            {
                ss << std::hex << dist(gen);
            }
            return ss.str();
        }

    } 
} 