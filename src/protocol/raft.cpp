#include <vmdt/raft.hpp>
#include <algorithm>
#include <random>
#include <iostream>

namespace vmdt
{
    namespace consensus
    {
        RaftNode::RaftNode(
            NodeId node_id,
            std::vector<NodeId> cluster_nodes,
            std::shared_ptr<NetworkInterface> network)
            : state_(std::make_unique<ConsensusState>(node_id, cluster_nodes)),
              network_(network),
              node_id_(node_id),
              cluster_nodes_(cluster_nodes),
              running_(false)
        {
            reset_election_timer();

            
            for (const auto &node : cluster_nodes_)
            {
                if (node != node_id_)
                {
                    replication_state_[node] = {1, 0, std::chrono::steady_clock::now()};
                }
            }
        }

        RaftNode::~RaftNode()
        {
            stop();
        }

        void RaftNode::start()
        {
            running_ = true;
            raft_thread_ = std::thread(&RaftNode::raft_main_loop, this);
        }

        void RaftNode::stop()
        {
            running_ = false;
            cv_.notify_all();
            if (raft_thread_.joinable())
            {
                raft_thread_.join();
            }
        }

        bool RaftNode::submit_log_entry(const SessionIntent &intent)
        {
            std::unique_lock<std::mutex> lock(mutex_);

            
            if (!is_leader())
            {
                return false;
            }

            
            LogEntry entry;
            entry.term = state_->get_current_term();
            entry.index = state_->get_last_log_index() + 1;
            entry.intent = intent;

            
            state_->append_entry(entry);

            
            cv_.notify_one();

            return true;
        }

        std::vector<SessionIntent> RaftNode::read_log()
        {
            return state_->get_committed_sessions();
        }

        bool RaftNode::is_leader() const
        {
            return state_->get_state() == NodeState::LEADER;
        }

        NodeId RaftNode::current_leader() const
        {
            return state_->get_leader_id();
        }

        RequestVoteResponse RaftNode::handle_request_vote(const RequestVoteRequest &req)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            RequestVoteResponse resp;
            resp.term = state_->get_current_term();

            
            if (req.term < state_->get_current_term())
            {
                resp.vote_granted = false;
                return resp;
            }

            
            if (req.term > state_->get_current_term())
            {
                state_->become_follower(req.term);
                reset_election_timer();
            }

            
            resp.vote_granted = state_->request_vote(req);
            resp.term = state_->get_current_term();

            if (resp.vote_granted)
            {
                reset_election_timer();
            }

            return resp;
        }

        AppendEntriesResponse RaftNode::handle_append_entries(const AppendEntriesRequest &req)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            AppendEntriesResponse resp;
            resp.term = state_->get_current_term();
            resp.success = false;
            resp.match_index = 0;

            
            if (req.term < state_->get_current_term())
            {
                return resp;
            }

            
            
            if (req.term > state_->get_current_term())
            {
                state_->become_follower(req.term);
            }

            
            reset_election_timer();

            
            if (state_->get_state() == NodeState::FOLLOWER)
            {
                
                
            }

            
            resp.success = append_entries_from_leader(req);
            resp.term = state_->get_current_term();

            if (resp.success)
            {
                
                if (!req.entries.empty())
                {
                    resp.match_index = req.entries.back().index;
                }
                else
                {
                    resp.match_index = req.prev_log_index;
                }

                
                if (req.leader_commit > state_->get_commit_index())
                {
                    LogIndex new_commit = std::min(req.leader_commit, state_->get_last_log_index());
                    state_->set_commit_index(new_commit);
                    apply_committed_entries();
                }
            }

            return resp;
        }

        void RaftNode::reset_election_timer()
        {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dist(MIN_ELECTION_TIMEOUT_MS, MAX_ELECTION_TIMEOUT_MS);

            auto timeout_ms = std::chrono::milliseconds(dist(gen));
            election_deadline_ = std::chrono::steady_clock::now() + timeout_ms;
        }

        bool RaftNode::is_election_timeout() const
        {
            return std::chrono::steady_clock::now() >= election_deadline_;
        }

        void RaftNode::raft_main_loop()
        {
            while (running_)
            {
                NodeState current_state = state_->get_state();

                switch (current_state)
                {
                case NodeState::FOLLOWER:
                    run_as_follower();
                    break;
                case NodeState::CANDIDATE:
                    run_as_candidate();
                    break;
                case NodeState::LEADER:
                    run_as_leader();
                    break;
                }

                
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }

        void RaftNode::run_as_follower()
        {
            std::unique_lock<std::mutex> lock(mutex_);

            
            auto timeout = election_deadline_ - std::chrono::steady_clock::now();
            if (timeout > std::chrono::milliseconds(0))
            {
                cv_.wait_for(lock, timeout);
            }

            
            if (is_election_timeout())
            {
                
                start_election();
            }
        }

        void RaftNode::run_as_candidate()
        {
            std::unique_lock<std::mutex> lock(mutex_);

            
            auto timeout = election_deadline_ - std::chrono::steady_clock::now();
            if (timeout > std::chrono::milliseconds(0))
            {
                cv_.wait_for(lock, timeout);
            }

            
            if (state_->has_majority_votes(cluster_nodes_.size()))
            {
                state_->become_leader();

                
                LogIndex next_index = state_->get_last_log_index() + 1;
                for (auto &[node_id, rep_state] : replication_state_)
                {
                    rep_state.next_index = next_index;
                    rep_state.match_index = 0;
                }

                
                lock.unlock();
                send_append_entries_to_all();
                return;
            }

            
            if (is_election_timeout())
            {
                
                start_election();
            }
        }

        void RaftNode::run_as_leader()
        {
            std::unique_lock<std::mutex> lock(mutex_);

            
            cv_.wait_for(lock, std::chrono::milliseconds(HEARTBEAT_INTERVAL_MS));

            lock.unlock();

            
            send_append_entries_to_all();

            
            advance_commit_index();
        }

        void RaftNode::start_election()
        {
            

            state_->become_candidate();
            reset_election_timer();

            
            send_vote_requests();
        }

        void RaftNode::send_vote_requests()
        {
            
            RequestVoteRequest req;
            req.term = state_->get_current_term();
            req.candidate_id = node_id_;
            req.last_log_index = state_->get_last_log_index();
            req.last_log_term = state_->get_last_log_term();

            
            for (const auto &node : cluster_nodes_)
            {
                if (node != node_id_)
                {
                    
                    network_->send_request_vote(node, req);
                }
            }
        }

        void RaftNode::process_vote_response(NodeId from, const RequestVoteResponse &resp)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            
            if (state_->get_state() != NodeState::CANDIDATE)
            {
                return;
            }

            
            if (resp.term > state_->get_current_term())
            {
                state_->become_follower(resp.term);
                reset_election_timer();
                return;
            }

            
            if (resp.vote_granted)
            {
                state_->record_vote(from);
            }

            
            cv_.notify_one();
        }

        void RaftNode::send_append_entries_to_all()
        {
            for (const auto &node : cluster_nodes_)
            {
                if (node != node_id_)
                {
                    send_append_entries_to(node);
                }
            }
        }

        void RaftNode::send_append_entries_to(NodeId target)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            
            if (!is_leader())
            {
                return;
            }

            auto &rep_state = replication_state_[target];

            
            AppendEntriesRequest req;
            req.term = state_->get_current_term();
            req.leader_id = node_id_;
            req.prev_log_index = rep_state.next_index - 1;
            req.prev_log_term = 0;

            
            if (req.prev_log_index > 0)
            {
                try
                {
                    LogEntry prev_entry = state_->get_entry(req.prev_log_index);
                    req.prev_log_term = prev_entry.term;
                }
                catch (...)
                {
                    
                    rep_state.next_index = 1;
                    return;
                }
            }

            
            req.entries = state_->get_entries_from(rep_state.next_index);
            req.leader_commit = state_->get_commit_index();

            
            network_->send_append_entries(target, req);
        }

        void RaftNode::process_append_entries_response(
            NodeId from,
            const AppendEntriesResponse &resp,
            LogIndex sent_prev_log_index)
        {
            std::lock_guard<std::mutex> lock(mutex_);

            
            if (!is_leader())
            {
                return;
            }

            
            if (resp.term > state_->get_current_term())
            {
                state_->become_follower(resp.term);
                reset_election_timer();
                return;
            }

            auto &rep_state = replication_state_[from];

            if (resp.success)
            {
                
                rep_state.match_index = resp.match_index;
                rep_state.next_index = resp.match_index + 1;
                rep_state.last_response = std::chrono::steady_clock::now();
            }
            else
            {
                
                if (rep_state.next_index > 1)
                {
                    rep_state.next_index--;
                }
            }

            
            cv_.notify_one();
        }

        void RaftNode::advance_commit_index()
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (!is_leader())
            {
                return;
            }

            
            LogIndex current_commit = state_->get_commit_index();
            LogIndex last_log_index = state_->get_last_log_index();

            for (LogIndex n = last_log_index; n > current_commit; n--)
            {
                
                if (count_matching_nodes(n) > cluster_nodes_.size() / 2)
                {
                    
                    try
                    {
                        LogEntry entry = state_->get_entry(n);
                        if (entry.term == state_->get_current_term())
                        {
                            state_->set_commit_index(n);
                            apply_committed_entries();
                            break;
                        }
                    }
                    catch (...)
                    {
                        
                    }
                }
            }
        }

        void RaftNode::apply_committed_entries()
        {
            
            
            
        }

        bool RaftNode::append_entries_from_leader(const AppendEntriesRequest &req)
        {
            

            
            if (req.prev_log_index > 0)
            {
                if (req.prev_log_index > state_->get_last_log_index())
                {
                    
                    return false;
                }

                try
                {
                    LogEntry prev_entry = state_->get_entry(req.prev_log_index);
                    if (prev_entry.term != req.prev_log_term)
                    {
                        
                        
                        return false;
                    }
                }
                catch (...)
                {
                    return false;
                }
            }

            
            for (const auto &entry : req.entries)
            {
                
                
                if (entry.index == state_->get_last_log_index() + 1)
                {
                    state_->append_entry(entry);
                }
            }

            return true;
        }

        LogIndex RaftNode::majority_match_index() const
        {
            
            std::vector<LogIndex> match_indices;
            match_indices.push_back(state_->get_last_log_index());

            for (const auto &[node_id, rep_state] : replication_state_)
            {
                match_indices.push_back(rep_state.match_index);
            }

            
            std::sort(match_indices.begin(), match_indices.end());
            size_t majority_idx = match_indices.size() / 2;
            return match_indices[majority_idx];
        }

        size_t RaftNode::count_matching_nodes(LogIndex index) const
        {
            size_t count = 1; 

            for (const auto &[node_id, rep_state] : replication_state_)
            {
                if (rep_state.match_index >= index)
                {
                    count++;
                }
            }

            return count;
        }

        RaftCluster::RaftCluster(size_t num_nodes)
        {
            nodes_.reserve(num_nodes);
        }

        RaftCluster::~RaftCluster()
        {
            stop_all();
        }

        void RaftCluster::add_node(std::shared_ptr<RaftNode> node)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            nodes_.push_back(node);
        }

        std::vector<std::shared_ptr<RaftNode>> RaftCluster::get_nodes() const
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return nodes_;
        }

        std::shared_ptr<RaftNode> RaftCluster::get_leader() const
        {
            std::lock_guard<std::mutex> lock(mutex_);

            for (const auto &node : nodes_)
            {
                if (node->is_leader())
                {
                    return node;
                }
            }

            return nullptr;
        }

        bool RaftCluster::submit_intent(const SessionIntent &intent)
        {
            auto leader = get_leader();
            if (!leader)
            {
                return false;
            }

            return leader->submit_log_entry(intent);
        }

        std::vector<SessionIntent> RaftCluster::read_committed_log() const
        {
            std::lock_guard<std::mutex> lock(mutex_);

            if (nodes_.empty())
            {
                return {};
            }

            
            return nodes_[0]->read_log();
        }

        void RaftCluster::start_all()
        {
            std::lock_guard<std::mutex> lock(mutex_);

            for (auto &node : nodes_)
            {
                node->start();
            }
        }

        void RaftCluster::stop_all()
        {
            std::lock_guard<std::mutex> lock(mutex_);

            for (auto &node : nodes_)
            {
                node->stop();
            }
        }

        bool RaftCluster::wait_for_leader(std::chrono::milliseconds timeout)
        {
            auto deadline = std::chrono::steady_clock::now() + timeout;

            while (std::chrono::steady_clock::now() < deadline)
            {
                if (get_leader() != nullptr)
                {
                    return true;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            return false;
        }

        std::shared_ptr<RaftCluster> create_test_cluster(size_t num_nodes)
        {
            auto cluster = std::make_shared<RaftCluster>(num_nodes);

            
            std::vector<NodeId> node_ids;
            for (size_t i = 0; i < num_nodes; i++)
            {
                node_ids.push_back("node_" + std::to_string(i + 1));
            }

            
            
            class SimpleNetwork : public NetworkInterface
            {
            public:
                bool send_request_vote(const NodeId &target, const RequestVoteRequest &req) override
                {
                    
                    return true;
                }

                bool send_append_entries(const NodeId &target, const AppendEntriesRequest &req) override
                {
                    
                    return true;
                }

                void on_request_vote_received(
                    const NodeId &from,
                    const RequestVoteRequest &req,
                    std::function<void(RequestVoteResponse)> respond) override
                {
                    
                }

                void on_append_entries_received(
                    const NodeId &from,
                    const AppendEntriesRequest &req,
                    std::function<void(AppendEntriesResponse)> respond) override
                {
                    
                }
            };

            auto network = std::make_shared<SimpleNetwork>();

            
            for (const auto &node_id : node_ids)
            {
                auto node = std::make_shared<RaftNode>(node_id, node_ids, network);
                cluster->add_node(node);
            }

            return cluster;
        }

        std::vector<uint8_t> serialize_request_vote(const RequestVoteRequest &req)
        {
            return req.serialize();
        }

        RequestVoteRequest deserialize_request_vote(const std::vector<uint8_t> &data)
        {
            return RequestVoteRequest::deserialize(data);
        }

        std::vector<uint8_t> serialize_append_entries(const AppendEntriesRequest &req)
        {
            return req.serialize();
        }

        AppendEntriesRequest deserialize_append_entries(const std::vector<uint8_t> &data)
        {
            return AppendEntriesRequest::deserialize(data);
        }

    } 
} 