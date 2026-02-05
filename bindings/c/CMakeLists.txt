# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

cmake_minimum_required(VERSION 3.22)
project(opendal-c)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

option(TEST_ENABLE_ASAN "Enable AddressSanitizer for tests" OFF)

# Disabled by default, it can be enabled with -DUSE_GTEST=ON

# force the compiler to support these standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# for GoogleTest, it should be no less than C++11
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(DEP_DIR "${PROJECT_SOURCE_DIR}/deps/3rd/usr/local/oceanbase/deps/devel")
set(TOOL_DIR "${PROJECT_SOURCE_DIR}/deps/3rd/usr/local/oceanbase/devtools")
message(NOTICE "-- DEP_DIR: ${DEP_DIR}")
message(NOTICE "-- TOOL_DIR: ${TOOL_DIR}")
include_directories(
    ${DEP_DIR}/include
    ${TOOL_DIR}/include
)

link_directories(
    ${DEP_DIR}/lib
    ${TOOL_DIR}/lib
    ${TOOL_DIR}/lib64
)
set(stdcxx_shared "${TOOL_DIR}/lib64/libstdc++.so.6")


set(CARGO_DIST_DIR "${PROJECT_SOURCE_DIR}/target/debug")
if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_BUILD_TYPE "--release")
    set(CARGO_DIST_DIR "${PROJECT_SOURCE_DIR}/target/release")
endif()

set(OPENDAL_STATIC_LIB "${CARGO_DIST_DIR}/libopendal_c${CMAKE_STATIC_LIBRARY_SUFFIX}")
set(OPENDAL_SHARED_LIB "${CARGO_DIST_DIR}/libopendal_c${CMAKE_SHARED_LIBRARY_SUFFIX}")
message(NOTICE "-- OpenDAL C static lib: ${OPENDAL_STATIC_LIB}")
message(NOTICE "-- OpenDAL C shared lib: ${OPENDAL_SHARED_LIB}")

# custom target for cargo build
# for tokio-console: RUSTFLAGS=\"--cfg tokio_unstable\" 
# for debug_log: RUSTFLAGS=\"-C debuginfo=2 -C force-frame-pointers=yes -C opt-level=0\"
add_custom_target(cargo_build
    COMMAND sh -c "cargo build ${CARGO_BUILD_TYPE}"
    BYPRODUCTS  ${OPENDAL_STATIC_LIB} ${OPENDAL_SHARED_LIB}
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
)

# cmake target for static lib
add_library(opendal_c_static INTERFACE)
target_link_libraries(opendal_c_static INTERFACE ${OPENDAL_STATIC_LIB})
target_include_directories(opendal_c_static INTERFACE include)
add_dependencies(opendal_c_static cargo_build)

# cmake target for shared lib
add_library(opendal_c_shared INTERFACE)
target_link_libraries(opendal_c_shared INTERFACE ${OPENDAL_SHARED_LIB})
target_include_directories(opendal_c_shared INTERFACE include)
add_dependencies(opendal_c_shared cargo_build)

enable_testing()

function(add_obdal_test target_name)
    add_executable(${target_name} ${ARGN})
    target_link_libraries(${target_name} PRIVATE opendal_c_shared gtest gmock -lpthread -ldl)
    target_link_libraries(${target_name} PRIVATE ${stdcxx_shared})
    target_link_options(${target_name} PRIVATE -rdynamic)
    message(STATUS "Linking with: ${stdcxx_shared}")
endfunction()

function(add_test_with_service target_name)
add_test(NAME ${target_name}_oss COMMAND ${target_name} --service oss)
    add_test(NAME ${target_name}_s3 COMMAND ${target_name} --service s3)
    add_test(NAME ${target_name}_azblob COMMAND ${target_name} --service azblob)
    add_test(NAME ${target_name}_cos COMMAND ${target_name} --service cos)
    add_test(NAME ${target_name}_obs COMMAND ${target_name} --service obs)
    add_test(NAME ${target_name}_gcs COMMAND ${target_name} --service gcs)
    add_test(NAME ${target_name}_bos COMMAND ${target_name} --service bos)
endfunction()

add_obdal_test(obdal_test tests/obdal_test.h tests/obdal_test.cpp)
add_obdal_test(obdal_async_test tests/obdal_test.h tests/obdal_async_test.cpp)
add_obdal_test(obdal_retry_test tests/obdal_retry_test.cpp)
add_obdal_test(obdal_worm_test tests/obdal_worm_test.cpp)

add_test_with_service(obdal_test)
add_test_with_service(obdal_async_test)

# Note: The following tests are not added to ctest due to special requirements:
# - obdal_retry_test: Requires MinIO with IPv4 endpoint configuration
# - obdal_worm_test: Requires OSS bucket with WORM (Write Once Read Many) policy enabled

if (TEST_ENABLE_ASAN)
    # target_compile_options(tests PRIVATE -fsanitize=address)
    # target_link_options(tests PRIVATE -fsanitize=address)

    target_compile_options(obdal_test PRIVATE -fsanitize=address)
    target_link_options(obdal_test PRIVATE -fsanitize=address)

    target_compile_options(obdal_async_test PRIVATE -fsanitize=address)
    target_link_options(obdal_async_test PRIVATE -fsanitize=address)
endif()

# 设置 RPATH
set_target_properties(obdal_test PROPERTIES
    BUILD_RPATH ${TOOL_DIR}/lib64/
    INSTALL_RPATH ${TOOL_DIR}/lib64/
)

install(
    FILES ${OPENDAL_STATIC_LIB}
    DESTINATION lib
)

# 安装头文件
install(
    DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)