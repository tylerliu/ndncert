# cmake version to be used
cmake_minimum_required(VERSION 3.5)

# project name
project(ndncert)

# flags
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)
if (HAVE_TESTS)
    add_compile_definitions(NDNCERT_HAVE_TESTS)
endif(HAVE_TESTS)

# dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(NDN_CXX REQUIRED libndn-cxx)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

pkg_check_modules(NDNMPS libndnmps)

# files
file(GLOB_RECURSE NDNCERT_LIB_SOURCE_FILES "src/*.cpp" "src/**/*.cpp")
if (${NDNMPS_FOUND})
    message("Found MPS library. Adding...")
    add_compile_definitions(NDNCERT_HAS_NDNMPS)
    file(GLOB_RECURSE NDNCERT_MPS_SOURCE_FILES "mps-src/*.cpp" "mps-src/**/*.cpp")
endif(${NDNMPS_FOUND})

# include
include_directories(${NDN_CXX_INCLUDE_DIRS})
include_directories(src)
include_directories(build/src)
if (${NDNMPS_FOUND})
    include_directories(mps-src)
endif(${NDNMPS_FOUND})

# link
link_directories(${NDN_CXX_LIBRARY_DIRS})

# target

add_library(ndn-cert SHARED ${NDNCERT_LIB_SOURCE_FILES} ${NDNCERT_MPS_SOURCE_FILES})
target_compile_options(ndn-cert PUBLIC ${NDN_CXX_CFLAGS})
target_link_libraries(ndn-cert PUBLIC ${NDN_CXX_LIBRARIES})
if (${NDNMPS_FOUND})
    target_compile_options(ndn-cert PUBLIC ${NDNMPS_CFLAGS})
    target_link_libraries(ndn-cert PUBLIC ${NDNMPS_LIBRARIES})
endif(${NDNMPS_FOUND})

add_subdirectory(tools)
add_subdirectory(tests)
