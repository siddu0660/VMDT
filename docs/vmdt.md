# VMDT Protocol Documentation

**Verifiable, Multipath, Decentralized Transport**

## Table of Contents

1. [Overview](#overview)
2. [What VMDT Does](#what-vmdt-does)
3. [The Protocol](#the-protocol)
4. [Why VMDT Over TCP or QUIC](#why-vmdt-over-tcp-or-quic)
5. [Protocol Header Format](#protocol-header-format)
6. [Messages in Protocol](#messages-in-protocol)
7. [SSMS Protocol and Usage](#ssms-protocol-and-usage)
8. [Working Principle](#working-principle)
9. [System Design](#system-design)
10. [How the Protocol App Works](#how-the-protocol-app-works)
11. [Cluster Management](#cluster-management)
12. [Additional Features](#additional-features)

---

## Overview

VMDT (Verifiable, Multipath, Decentralized Transport) is a novel transport protocol designed to provide secure, reliable, and efficient data transmission in peer-to-peer networks. It combines secret sharing, multipath routing, and decentralized cluster management to achieve high availability, fault tolerance, and privacy.

### Key Characteristics

- **Verifiable**: Uses cryptographic secret sharing to ensure data integrity and authenticity
- **Multipath**: Distributes data across multiple network paths simultaneously
- **Decentralized**: Operates in a peer-to-peer cluster without a single point of failure

---

## What VMDT Does

VMDT enables secure and reliable communication between peers in a decentralized network by:

1. **Secret Sharing**: Splits messages into multiple shares using Shamir's Secret Sharing Scheme (SSMS), where only `k` out of `n` shares are needed to reconstruct the original message
2. **Multipath Distribution**: Sends shares through different paths in the network cluster, increasing reliability and fault tolerance
3. **Cluster-Based Communication**: Organizes peers into clusters with configurable redundancy parameters (n, k)
4. **Reliable Delivery**: Implements a reliable data transfer (RDT) layer over UDP with acknowledgment and retransmission mechanisms
5. **Share Pool Management**: Maintains a distributed share pool where cluster members can claim shares, enabling efficient load balancing and redundancy

### Use Cases

- Secure messaging in untrusted networks
- File transfer with high availability requirements
- Distributed storage systems
- Privacy-preserving communication
- Fault-tolerant data transmission

---

## The Protocol

VMDT operates as a dual-layer protocol:

### 1. Control Layer (TCP)
- **Purpose**: Cluster management, peer discovery, and coordination
- **Transport**: TCP for reliable control message delivery
- **Format**: Human-readable ASCII messages
- **Port**: Configurable (default: 8080 for server)

### 2. Data Layer (UDP)
- **Purpose**: Actual data transmission (shares)
- **Transport**: UDP with custom RDT (Reliable Data Transfer) layer
- **Format**: Binary headers with variable payload
- **Port**: Dynamic P2P ports (registered per client)

### Protocol Stack

```
┌─────────────────────────────────────┐
│   Application Layer                 │
│   (Messages, Files)                 │
├─────────────────────────────────────┤
│   SSMS Layer                        │
│   (Secret Sharing)                  │
├─────────────────────────────────────┤
│   VMDT Protocol Layer               │
│   (Cluster Management, Routing)     │
├─────────────────────────────────────┤
│   RDT Layer (UDP)                   │
│   (Reliability, ACKs, Retransmit)   │
├─────────────────────────────────────┤
│   UDP/TCP                           │
│   (Transport)                       │
├─────────────────────────────────────┤
│   IP                                │
│   (Network)                         │
└─────────────────────────────────────┘
```

---

## Why VMDT Over TCP or QUIC

### Limitations of TCP

1. **Single Path**: TCP uses a single connection, making it vulnerable to path failures
2. **Head-of-Line Blocking**: Packet loss causes delays for all subsequent packets
3. **Centralized**: Requires a central server or direct connection
4. **No Built-in Privacy**: Data is transmitted in plaintext (without additional encryption)
5. **Limited Fault Tolerance**: Single point of failure in the connection

### Limitations of QUIC

1. **Single Path**: While QUIC supports connection migration, it still uses one path at a time
2. **Complexity**: Higher protocol complexity and overhead
3. **Server Dependency**: Still requires server infrastructure for many use cases
4. **Limited Decentralization**: Not designed for true peer-to-peer scenarios

### VMDT Advantages

1. **True Multipath**: Simultaneously uses multiple paths through cluster members
2. **Fault Tolerance**: Only `k` out of `n` shares needed; can tolerate `n-k` failures
3. **Decentralized**: No single point of failure; cluster-based architecture
4. **Privacy by Design**: Secret sharing ensures no single node sees complete data
5. **Verifiable**: Cryptographic guarantees for data integrity
6. **Load Balancing**: Share pool mechanism distributes load across cluster
7. **Adaptive**: Can dynamically adjust share distribution based on network conditions

### Performance Characteristics

- **Throughput**: Can exceed single-path protocols by utilizing multiple paths
- **Latency**: Parallel transmission reduces effective latency
- **Reliability**: Higher reliability due to redundancy (k-out-of-n)
- **Scalability**: Cluster-based design scales horizontally

---

## Protocol Header Format

### TCP Control Message Format

**Structure**: `VMDT/TCP/<VERSION>/<MSG_TYPE>/<PARAM1>/<PARAM2>/...\n`

**Example**:
```
VMDT/TCP/1.0/CREATE_CLUSTER/client_12345/5/3\n
```

**Fields**:
- `VMDT`: Magic identifier (4 bytes)
- `TCP`: Transport protocol identifier
- `1.0`: Protocol version
- `CREATE_CLUSTER`: Message type
- Parameters: Variable number of parameters separated by `/`
- `\n`: Message terminator

### UDP Data Packet Format

#### VMDT Header (64 bytes - ASCII, null-padded)

| Offset | Size | Field        | Description                          |
|--------|------|--------------|--------------------------------------|
| 0-3    | 4    | Magic        | "VMDT"                               |
| 4-7    | 4    | Version      | Protocol version (e.g., "1.0\0")     |
| 8-23   | 16   | Source ID    | Source client identifier             |
| 24-39  | 16   | Dest ID      | Destination client identifier        |
| 40-55  | 16   | Message ID   | Unique message identifier            |
| 56-59  | 4    | Share Index  | Share index (ASCII, e.g., "0001")    |
| 60-63  | 4    | Reserved     | Reserved for future use              |

#### RDT Header (16 bytes - Binary, network byte order)

| Offset | Size | Field        | Type      | Description                          |
|--------|------|--------------|-----------|--------------------------------------|
| 64-65  | 2    | Seq Num      | uint16_t  | Sequence number                      |
| 66-67  | 2    | Ack Num      | uint16_t  | Acknowledgment number                |
| 68     | 1    | Packet Type  | uint8_t   | RDTType (see below)                  |
| 69     | 1    | Flags        | uint8_t   | RDTFlags (see below)                 |
| 70-71  | 2    | Window Size  | uint16_t  | Receiver window size                 |
| 72-73  | 2    | Checksum     | uint16_t  | Optional checksum                    |
| 74-75  | 2    | Payload Len  | uint16_t  | Payload length in bytes              |
| 76-79  | 4    | Reserved     | uint8_t[4]| Reserved (zero-padded)               |

#### RDT Packet Types

```cpp
enum class RDTType : uint8_t {
    DATA = 0x01,        // Data packet
    ACK = 0x02,         // Acknowledgment
    NAK = 0x03,         // Negative acknowledgment
    SYN = 0x04,         // Synchronization
    FIN = 0x05,         // Finish
    HEARTBEAT = 0x06    // Heartbeat
};
```

#### RDT Flags

```cpp
enum class RDTFlags : uint8_t {
    NONE = 0x00,
    FINAL = 0x01,       // Final packet in sequence
    RETRANSMIT = 0x02,  // Retransmitted packet
    CHECKSUM = 0x04     // Checksum present
};
```

#### Payload

- **Variable length** (max 1472 bytes for UDP)
- Contains share data (base64 encoded or binary)
- Format depends on SSMS share structure

### Complete Packet Structure

```
┌─────────────────────────────────────────┐
│  VMDT Header (64 bytes)                 │
│  - Magic, Version, IDs, Share Index     │
├─────────────────────────────────────────┤
│  RDT Header (16 bytes)                  │
│  - Seq, Ack, Type, Flags, Length        │
├─────────────────────────────────────────┤
│  Payload (Variable, max 1472 bytes)     │
│  - Share data                           │
└─────────────────────────────────────────┘
Total: 80 bytes header + payload
```

---

## Messages in Protocol

### Control Messages (TCP)

#### Cluster Management

1. **CREATE_CLUSTER**
   - Format: `CREATE_CLUSTER|<client_id>|<n>|<k>`
   - Purpose: Create a new cluster with n total shares, k threshold
   - Response: `CLUSTER_CREATED|<cluster_id>`

2. **JOIN_CLUSTER**
   - Format: `JOIN_CLUSTER|<client_id>|<cluster_id>`
   - Purpose: Join an existing cluster
   - Response: `CLUSTER_JOINED|<cluster_id>`

3. **LEAVE_CLUSTER**
   - Format: `LEAVE_CLUSTER|<client_id>`
   - Purpose: Leave current cluster
   - Response: `OK` or `ERROR|<message>`

4. **LIST_CLUSTERS**
   - Format: `LIST_CLUSTERS|<client_id>`
   - Purpose: List all available clusters
   - Response: `CLUSTER_LIST|<cluster1_data>|...`

5. **GET_CLUSTER_MEMBERS**
   - Format: `GET_CLUSTER_MEMBERS|<client_id>`
   - Purpose: Get list of members in current cluster
   - Response: `CLUSTER_MEMBERS|<member1>|...`

#### Peer Discovery

6. **REGISTER_P2P_PORT**
   - Format: `REGISTER_P2P_PORT|<client_id>|<port>`
   - Purpose: Register P2P listening port with server
   - Response: `OK`

7. **GET_CLIENT_INFO**
   - Format: `GET_CLIENT_INFO|<client_id>|<target_client_id>`
   - Purpose: Get IP and port of a client
   - Response: `CLIENT_INFO|<ip>|<port>`

#### Message Transmission

8. **SEND_MESSAGE**
   - Format: `SEND_MESSAGE|<client_id>|<target_client_id>|<message>`
   - Purpose: Initiate message sending (triggers share distribution)
   - Response: `OK` or `ERROR|<message>`

9. **MESSAGE_SHARE**
   - Format: `MESSAGE_SHARE|<from>|<to>|<target>|<share_index>|<share_data>`
   - Purpose: Relay share through server (fallback mechanism)
   - Response: None (one-way)

10. **MESSAGE_RECEIVED**
    - Format: `MESSAGE_RECEIVED|<message_id>`
    - Purpose: Acknowledge message reconstruction
    - Response: None

#### Share Pool Management

11. **SHARE_POOL_ADD**
    - Format: `SHARE_POOL_ADD|<msg_id>|<sender>|<receiver>|<total>|<active>|<type>|<filename>|<share1>|...`
    - Purpose: Add shares to distributed pool
    - Response: None (broadcast)

12. **SHARE_POOL_CLAIM**
    - Format: `SHARE_POOL_CLAIM|<msg_id>|<claimer>|<share_index>`
    - Purpose: Claim a share from pool
    - Response: None (broadcast)

13. **SHARE_POOL_ACK**
    - Format: `SHARE_POOL_ACK|<msg_id>|<receiver>`
    - Purpose: Acknowledge successful reconstruction
    - Response: None

14. **SHARE_POOL_UNFREEZE**
    - Format: `SHARE_POOL_UNFREEZE|<msg_id>|<share_index>`
    - Purpose: Unfreeze a share (make it available)
    - Response: None

15. **SHARE_POOL_REMOVE**
    - Format: `SHARE_POOL_REMOVE|<msg_id>`
    - Purpose: Remove shares from pool after delivery
    - Response: None

#### Status Messages

16. **CLUSTER_READY**
    - Format: `CLUSTER_READY|<cluster_id>`
    - Purpose: Notify that cluster has enough members
    - Response: None (broadcast)

17. **ERROR**
    - Format: `ERROR|<error_message>`
    - Purpose: Report error condition
    - Response: None

---

## SSMS Protocol and Usage

### Overview

SSMS (Secret Sharing with Message Splitting) is a cryptographic protocol that combines:
- **AES-256-CTR encryption** for data confidentiality
- **Shamir's Secret Sharing Scheme** for key distribution
- **Galois Field arithmetic (GF(256))** for polynomial operations

### How SSMS Works

#### 1. Secret Splitting

When a message needs to be sent:

1. **Encryption**: The original message is encrypted using AES-256-CTR with a randomly generated key and nonce
2. **Key Sharing**: The encryption key is split into `n` shares using Shamir's Secret Sharing with threshold `k`
3. **Share Creation**: Each of the `n` shares contains:
   - The encrypted data (same for all shares)
   - A unique key share
   - The nonce (same for all shares)
   - Metadata (original size, threshold, share index)

#### 2. Share Structure

Each share contains:
```
┌─────────────────────────────────────┐
│ Share Index (1 byte)                │
├─────────────────────────────────────┤
│ Original Size (4 bytes, big-endian) │
├─────────────────────────────────────┤
│ Threshold k (1 byte)                │
├─────────────────────────────────────┤
│ Key Share Size (4 bytes)            │
├─────────────────────────────────────┤
│ Nonce (12 bytes)                    │
├─────────────────────────────────────┤
│ Key Share (32 bytes)                │
├─────────────────────────────────────┤
│ Encrypted Data (variable)           │
└─────────────────────────────────────┘
```

#### 3. Secret Reconstruction

To reconstruct the original message:

1. **Collect Shares**: Gather at least `k` shares
2. **Key Reconstruction**: Use Lagrange interpolation in GF(256) to reconstruct the master key from `k` key shares
3. **Decryption**: Decrypt the encrypted data using the reconstructed key and nonce
4. **Truncation**: Resize to original message length

### SSMS in VMDT

#### Integration Points

1. **Message Sending**:
   ```cpp
   // Client splits message using SSMS
   std::vector<std::vector<uint8_t>> shares = 
       SSMS::split_simple(message_bytes, cluster_k_, cluster_n_);
   ```

2. **Share Distribution**:
   - Shares are distributed to different cluster members
   - Each member receives one or more shares
   - Shares are stored in the share pool

3. **Message Reconstruction**:
   ```cpp
   // Receiver collects k shares and reconstructs
   std::vector<uint8_t> reconstructed = 
       SSMS::reconstruct_simple(collected_shares);
   ```

#### Security Properties

1. **Confidentiality**: No single node can decrypt without `k` shares
2. **Integrity**: Any modification to shares is detectable
3. **Availability**: System works as long as `k` out of `n` shares are available
4. **Forward Secrecy**: Each message uses a unique encryption key

#### Performance Considerations

- **Overhead**: Each share is larger than original (includes encrypted data + key share)
- **Storage**: Total storage is `n × (encrypted_size + key_share_size + metadata)`
- **Computation**: Polynomial operations in GF(256) are efficient (table-based)

---

## Working Principle

### High-Level Flow

```
┌──────────┐                    ┌──────────┐
│  Sender  │                    │ Receiver │
└────┬─────┘                    └────┬─────┘
     │                               │
     │ 1. Create/Join Cluster        │
     ├───────────────────────────────┤
     │                               │
     │ 2. Split Message (SSMS)       │
     │    → n shares, need k         │
     │                               │
     │ 3. Distribute Shares          │
     │    ├─→ Cluster Member 1       │
     │    ├─→ Cluster Member 2       │
     │    ├─→ Cluster Member 3       │
     │    └─→ ...                    │
     │                               │
     │ 4. Share Pool Management      │
     │    - Active shares (k)        │
     │    - Frozen shares (n-k)      │
     │                               │
     │ 5. Receiver Claims Shares     │
     │    - Collects k shares        │
     │                               │
     │ 6. Reconstruct Message        │
     │    - SSMS reconstruction      │
     │                               │
     │ 7. Acknowledge                │
     │    - Share pool cleanup       │
     └───────────────────────────────┘
```

### Detailed Steps

#### Step 1: Cluster Formation

1. Client connects to VMDT server via TCP
2. Client creates or joins a cluster with parameters (n, k)
3. Server tracks cluster membership
4. When cluster has enough members, `CLUSTER_READY` is broadcast

#### Step 2: Message Preparation

1. Sender prepares message (text or file)
2. Message is split using SSMS into `n` shares
3. Each share is base64 encoded for transmission
4. Shares are saved locally for backup

#### Step 3: Share Distribution

1. Sender broadcasts `SHARE_POOL_ADD` to all cluster members
2. Initial state: `k` shares are ACTIVE, `n-k` shares are FROZEN
3. Cluster members store shares in their local share pool

#### Step 4: Share Claiming

1. Receiver checks share pool for messages addressed to them
2. Receiver claims `k` ACTIVE shares
3. If not enough ACTIVE shares, FROZEN shares are activated
4. Claimed shares are marked as CLAIMED

#### Step 5: Direct P2P Transfer (Optional)

1. Receiver can request direct P2P transfer of shares
2. Uses UDP with RDT layer for reliability
3. Shares are sent with VMDT+RDT headers
4. ACKs ensure delivery

#### Step 6: Message Reconstruction

1. Receiver collects at least `k` shares
2. Shares are decoded from base64
3. SSMS reconstruction recovers original message
4. Message is delivered to application

#### Step 7: Cleanup

1. Receiver sends `SHARE_POOL_ACK` to sender
2. Sender broadcasts `SHARE_POOL_REMOVE`
3. Cluster members clean up share pool entries

### Fault Tolerance

- **Share Loss**: If some shares are lost, receiver can still reconstruct with remaining shares (as long as ≥k)
- **Node Failure**: If a node fails, its shares are unavailable, but other nodes may have copies
- **Network Partition**: System continues to work as long as `k` nodes are reachable
- **Retransmission**: RDT layer handles packet loss and retransmission

---

## System Design

### Architecture Components

```
┌─────────────────────────────────────────────────────────────┐
│                    VMDT System Architecture                  │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Client 1   │         │   Client 2   │         │   Client 3   │
│              │         │              │         │              │
│ ┌──────────┐ │         │ ┌──────────┐ │         │ ┌──────────┐ │
│ │ P2P      │ │         │ │ P2P      │ │         │ │ P2P      │ │
│ │ Client   │ │         │ │ Client   │ │         │ │ Client   │ │
│ └────┬─────┘ │         │ └────┬─────┘ │         │ └────┬─────┘ │
│      │       │         │      │       │         │      │       │
│      │       │         │      │       │         │      │       │
│      └───────┼─────────┼──────┘       │         │      │       │
│              │         │              │         │      │       │
│              │         │              │         │      │       │
│              └─────────┼──────────────┼─────────┘      │       │
│                        │              │                │       │
│                        │              │                │       │
│                        └──────────────┼────────────────┘       │
│                                       │                        │
│                                       ▼                        │
│                              ┌──────────────┐                 │
│                              │ VMDT Server  │                 │
│                              │              │                 │
│                              │ - Cluster    │                 │
│                              │   Management │                 │
│                              │ - Peer       │                 │
│                              │   Discovery  │                 │
│                              │ - Message    │                 │
│                              │   Relay      │                 │
│                              └──────────────┘                 │
│                                       │                        │
└───────────────────────────────────────┼────────────────────────┘
                                        │
                                        │ TCP (Control)
                                        │ UDP (Data)
                                        │
```

### Component Details

#### 1. VMDT Server

**Responsibilities**:
- Cluster creation and management
- Client registration and discovery
- Message routing (fallback)
- Cluster state maintenance

**Data Structures**:
- `clusters_`: Map of cluster_id → Cluster
- `client_to_cluster_`: Map of client_id → cluster_id
- `client_to_p2p_port_`: Map of client_id → port
- `client_to_ip_`: Map of client_id → IP address

#### 2. P2P Client

**Responsibilities**:
- Cluster membership
- Message sending and receiving
- Share pool management
- P2P communication
- SSMS operations

**Data Structures**:
- `share_pool_`: Map of message_id → SharePoolEntry
- `pending_shares_`: Map of message_id → shares
- `cluster_n_`, `cluster_k_`: Cluster parameters

#### 3. Share Pool Entry

```cpp
struct SharePoolEntry {
    std::string sender_id;
    std::string receiver_id;
    std::map<int, std::pair<ShareState, std::string>> shares;
    int active_count;      // Number of ACTIVE shares
    int frozen_count;      // Number of FROZEN shares
    int claimed_count;     // Number of CLAIMED shares
    bool is_file;          // Whether this is a file transfer
    std::string filename;  // Original filename (if file)
};
```

#### 4. RDT Layer

**Features**:
- Sequence numbers for ordering
- Acknowledgments for reliability
- Retransmission on timeout
- Window-based flow control
- Checksum verification

### Data Flow

#### Sending a Message

```
Application
    │
    ▼
P2PClient::send_message()
    │
    ├─→ SSMS::split_simple()  [Split into n shares]
    │
    ├─→ broadcast_share_pool_add()  [Add to share pool]
    │
    ├─→ send_share_to_peer()  [Direct P2P if needed]
    │   │
    │   └─→ UDP with RDT headers
    │
    └─→ Save shares to disk
```

#### Receiving a Message

```
UDP Socket / Share Pool
    │
    ▼
P2PClient::check_for_messages()
    │
    ├─→ claim_share_from_pool()  [Claim k shares]
    │
    ├─→ Collect shares in pending_shares_
    │
    ├─→ reconstruct_message()  [When k shares available]
    │   │
    │   └─→ SSMS::reconstruct_simple()
    │
    └─→ Deliver to application
```

---

## How the Protocol App Works

### Application Structure

The VMDT application consists of:

1. **Server Application** (`p2p_server`)
   - Command-line interface
   - Cluster management
   - Client coordination

2. **Client Application** (`p2p_client`)
   - Command-line interface
   - Interactive messaging
   - File transfer

3. **GUI Applications** (`p2p_server_gui`, `p2p_client_gui`)
   - Qt-based graphical interfaces
   - Visual cluster status
   - Message history

### Client Workflow

#### Initialization

1. **Start Client**:
   ```bash
   ./p2p_client <server_host> <server_port>
   ```

2. **Connect to Server**:
   - Establishes TCP connection
   - Generates unique client ID
   - Registers P2P port

3. **Join/Create Cluster**:
   ```
   > create_cluster 5 3
   # Creates cluster with n=5, k=3
   ```

#### Sending Messages

1. **User Input**:
   ```
   > send client_67890 "Hello, World!"
   ```

2. **Processing**:
   - Message is split into 5 shares (k=3 needed)
   - Shares are added to share pool
   - Shares are distributed to cluster members

3. **Delivery**:
   - Receiver claims 3 shares
   - Message is reconstructed
   - Delivered to receiver

#### Receiving Messages

1. **Background Thread**:
   - Continuously checks for new messages
   - Monitors share pool
   - Processes incoming UDP packets

2. **Share Collection**:
   - Claims shares from pool
   - Collects direct P2P shares
   - Waits for k shares

3. **Reconstruction**:
   - Reconstructs message using SSMS
   - Displays to user
   - Sends acknowledgment

### Server Workflow

#### Initialization

1. **Start Server**:
   ```bash
   ./p2p_server <port>
   ```

2. **Listen for Clients**:
   - Accepts TCP connections
   - Spawns handler thread per client
   - Maintains client registry

#### Cluster Management

1. **Cluster Creation**:
   - Validates parameters (n, k)
   - Generates unique cluster ID
   - Adds creator as first member

2. **Member Joining**:
   - Validates cluster exists
   - Checks capacity (n members max)
   - Adds member to cluster

3. **Cluster Ready**:
   - When cluster has n members
   - Broadcasts CLUSTER_READY
   - Enables message transmission

### Error Handling

1. **Connection Loss**:
   - Client reconnects automatically
   - Server removes disconnected clients
   - Cluster state is updated

2. **Share Loss**:
   - Receiver requests retransmission
   - Frozen shares are activated
   - Alternative paths are used

3. **Cluster Failure**:
   - Members can leave and rejoin
   - New clusters can be created
   - State is recovered from server

---

## Cluster Management

### Cluster Lifecycle

#### 1. Creation

```
Client A → Server: CREATE_CLUSTER client_A 5 3
Server → Client A: CLUSTER_CREATED cluster_12345
```

**Parameters**:
- `n = 5`: Total number of shares
- `k = 3`: Threshold (minimum shares needed)

**State**:
- Cluster ID: `cluster_12345`
- Creator: `client_A`
- Members: `{client_A}`
- Status: Not ready (needs 4 more members)

#### 2. Joining

```
Client B → Server: JOIN_CLUSTER client_B cluster_12345
Server → Client B: CLUSTER_JOINED cluster_12345
Server → All Members: (internal update)
```

**Process**:
1. Server validates cluster exists
2. Server checks cluster not full
3. Server adds client to cluster
4. Server checks if cluster is ready

#### 3. Ready State

When cluster has `n` members:

```
Server → All Members: CLUSTER_READY cluster_12345
```

**Effects**:
- Members can now send messages
- Share pool is activated
- P2P connections are established

#### 4. Member Departure

```
Client X → Server: LEAVE_CLUSTER client_X
Server → Client X: OK
Server → Remaining Members: (internal update)
```

**Effects**:
- Member removed from cluster
- Cluster may become not ready
- Shares held by departed member are lost (but k-out-of-n still works)

### Cluster State Machine

```
┌─────────────┐
│   EMPTY     │
└──────┬──────┘
       │ CREATE_CLUSTER
       ▼
┌─────────────┐
│  CREATING   │ (1 member)
└──────┬──────┘
       │ JOIN (n-1 times)
       ▼
┌─────────────┐
│    READY    │ (n members)
└──────┬──────┘
       │ LEAVE
       ▼
┌─────────────┐
│  DEGRADED   │ (< n members, but ≥ k)
└─────────────┘
```

### Share Distribution Strategy

#### Initial Distribution

When a message is sent:

1. **Share Creation**: `n` shares are created
2. **Active Shares**: First `k` shares are marked ACTIVE
3. **Frozen Shares**: Remaining `n-k` shares are marked FROZEN
4. **Broadcast**: All shares are broadcast to cluster

#### Dynamic Rebalancing

1. **Claiming**: Receiver claims ACTIVE shares first
2. **Unfreezing**: If needed, FROZEN shares are activated
3. **Load Balancing**: Multiple receivers can claim different shares

### Consensus (Optional)

The system includes a Raft-based consensus module for advanced cluster coordination:

- **Leader Election**: Cluster elects a leader
- **Log Replication**: Session intents are logged
- **Share Assignment**: Leader assigns shares to nodes
- **Fault Tolerance**: Handles leader failures

**Usage**: Currently optional; basic cluster management doesn't require it.

---

## Additional Features

### File Transfer

VMDT supports file transfer in addition to text messages:

1. **File Detection**: Automatically detects file paths
2. **File Reading**: Reads file as binary data
3. **Share Splitting**: Splits file using SSMS
4. **Metadata**: Includes filename in share pool
5. **Reconstruction**: Reconstructs file with original name

**Example**:
```
> send client_67890 /path/to/file.txt
```

### Share Pool States

Shares in the pool have three states:

1. **ACTIVE**: Available for claiming
2. **FROZEN**: Reserved, can be activated if needed
3. **CLAIMED**: Already claimed by a receiver

**State Transitions**:
```
ACTIVE → CLAIMED (when claimed)
FROZEN → ACTIVE (when unfrozen)
```

### Compression (Future)

The protocol design supports optional compression:

- Data can be compressed before SSMS splitting
- Reduces network bandwidth
- Increases effective throughput

### Monitoring and Analysis

Tools provided for protocol analysis:

1. **Packet Capture**: `scripts/capture_packets.sh`
2. **Packet Parsing**: `scripts/parse_vmdt_pcap.py`
3. **Benchmarking**: `analysis/benchmark_runner.py`
4. **Visualization**: `analysis/plot_results.py`

### Security Considerations

1. **Encryption**: AES-256-CTR for data confidentiality
2. **Secret Sharing**: No single node sees complete data
3. **Verification**: Cryptographic integrity checks
4. **Access Control**: Cluster-based isolation

### Performance Optimizations

1. **Parallel Transmission**: Multiple shares sent simultaneously
2. **Early Termination**: Stop sending after k shares delivered
3. **Caching**: Share pool caching for efficiency
4. **Connection Reuse**: P2P connections are reused

### Limitations and Future Work

**Current Limitations**:
- No authentication/authorization
- No perfect forward secrecy between messages
- Limited to single cluster per client
- No NAT traversal

**Future Enhancements**:
- End-to-end encryption keys
- Multi-cluster support
- NAT traversal (STUN/TURN)
- Performance metrics dashboard
- Mobile client support

---

## Conclusion

VMDT provides a novel approach to secure, reliable, and decentralized communication by combining:

- **Secret Sharing** for privacy and fault tolerance
- **Multipath Routing** for reliability and performance
- **Decentralized Architecture** for scalability and resilience

The protocol is designed to be:
- **Simple** to understand and implement
- **Efficient** in resource usage
- **Robust** against failures
- **Secure** by design

For more information, see the source code in the `protocol/` directory and example applications in the `app/` directory.

=== Lines of Code by File Type ===

C++ Source Files (.cpp):
  3497 total

C++ Header Files (.hpp, .h):
 1705 total

Python Scripts (.py):
  417 total

Shell Scripts (.sh):
 212 total

