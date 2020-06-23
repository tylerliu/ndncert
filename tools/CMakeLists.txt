# cmake version to be used
cmake_minimum_required(VERSION 3.5)

add_executable(ndncert-ca-server ndncert-ca-server.cpp)
target_link_libraries(ndncert-ca-server PUBLIC ndn-cert)

add_executable(ndncert-ca-status ndncert-ca-status.cpp)
target_link_libraries(ndncert-ca-status PUBLIC ndn-cert)

add_executable(ndncert-client ndncert-client.cpp)
target_link_libraries(ndncert-client PUBLIC ndn-cert)