# cmake version to be used
cmake_minimum_required(VERSION 3.5)

find_package(PkgConfig REQUIRED)

if (${NDNMPS_FOUND})
    add_executable(ndnmps-signer ndncert-signer.cpp)
    target_link_libraries(ndnmps-signer PUBLIC ndn-cert)
    target_compile_options(ndnmps-signer PUBLIC ${NDNMPS_CFLAGS})
    target_link_libraries(ndnmps-signer PUBLIC ${NDNMPS_LIBRARIES})

    add_executable(demo-client demo-client.cpp)
    target_link_libraries(demo-client PUBLIC ndn-cert)
    target_compile_options(demo-client PUBLIC ${NDNMPS_CFLAGS})
    target_link_libraries(demo-client PUBLIC ${NDNMPS_LIBRARIES})
endif(${NDNMPS_FOUND})