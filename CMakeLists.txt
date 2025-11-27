cmake_minimum_required(VERSION 3.10)
project(P2PClusterSystem)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(SERVER_SRCS
    src/server/p2p_server.cpp
    src/server/server_main.cpp
    src/protocol/consensus.cpp
    src/protocol/raft.cpp
)

set(CLIENT_SRCS
    src/client/p2p_client.cpp
    src/client/client_main.cpp
    src/protocol/consensus.cpp
    src/protocol/raft.cpp
)

add_executable(p2p_server ${SERVER_SRCS})
target_link_libraries(p2p_server pthread)

add_executable(p2p_client ${CLIENT_SRCS})
target_link_libraries(p2p_client pthread)

