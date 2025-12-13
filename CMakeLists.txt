cmake_minimum_required(VERSION 3.10)
project(PersonalCloudPhase7)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(server server.cpp)
add_executable(client client.cpp)

target_link_libraries(server OpenSSL::Crypto)
target_link_libraries(client OpenSSL::Crypto)
