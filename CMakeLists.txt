cmake_minimum_required(VERSION 3.28.3)

project(charter-custody C CXX)

if(NOT CMAKE_PREFIX_PATH)
 set(CMAKE_PREFIX_PATH "/usr/local")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -fPIC -DBOOST_LOG_DYN_LINK")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INSTALL_RPATH "${CMAKE_PREFIX_PATH}/lib;${CMAKE_INSTALL_RPATH};${CMAKE_CURRENT_BINARY_DIR}")
set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH ON)
message(STATUS "CMAKE_PREFIX_PATH provided as ${CMAKE_PREFIX_PATH}")
message(STATUS "CMAKE_INSTALL_PREFIX provided as ${CMAKE_INSTALL_PREFIX}")
message(STATUS "CMAKE_INSTALL_RPATH provided as ${CMAKE_INSTALL_RPATH}")

if(APPLE)
  message(STATUS "Using .so instead of .dylib")
  set(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
endif()

option(WITH_TESTS "Build with tests" ON)
option(WITH_ASAN "Build with ASAN support" OFF)
option(WITH_TSAN "Build with TSAN support" OFF)
option(WITH_UBSAN "Build with UBSAN support" OFF)
option(WITH_STATIC_ANALYZER "Build with clang static analyzer" OFF)
option(WITH_CLANG_TIDY "Enable clang tidy" OFF)
option(WITH_COVERAGE "Enable gcov / llcov support" OFF)

if(WITH_ASAN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
endif()

if(WITH_TSAN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
endif()

if(WITH_UBSAN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
endif()

if(WITH_ASAN OR WITH_TSAN OR WITH_UBSAN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -rdynamic -g3 -fno-omit-frame-pointer")
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g3 -fno-omit-frame-pointer")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "DebWithRelInfo")
  message(STATUS "Setting source file path for debugging")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdebug-prefix-map=/build/agent/work=${CMAKE_SOURCE_DIR} -ffile-prefix-map=/build/agent/work=${CMAKE_SOURCE_DIR}")
endif()

if(WITH_STATIC_ANALYZER)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Xclang -analyze")
endif()

if(WITH_CLANG_TIDY)
  find_program(CLANG_TIDY_EXECUTABLE NAMES clang-tidy)
  if(CLANG_TIDY_EXECUTABLE)
    message(STATUS "clang-tidy found: ${CLANG_TIDY_EXECUTABLE}")
    set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXECUTABLE};-checks=*")
  else()
    message(WARNING "clang-tidy not found")
  endif()
endif()

if(UNIX AND NOT APPLE AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -rdynamic")
endif()

add_library(coverage_config INTERFACE)
if(WITH_COVERAGE)
  target_compile_options(coverage_config INTERFACE -O0 -g -fno-inline -fno-omit-frame-pointer)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(coverage_config INTERFACE --coverage -fprofile-update=atomic)
    target_link_options(coverage_config INTERFACE --coverage)
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(coverage_config INTERFACE -fprofile-instr-generate -fcoverage-mapping)
    target_link_options(coverage_config INTERFACE -fprofile-instr-generate)
  endif()
endif()

if(NOT Boost_FOUND)
  find_package(Boost 1.90.0 REQUIRED)
endif()

if(WITH_TESTS AND NOT GTest_FOUND)
  find_package(GTest REQUIRED)
endif()

if(NOT TARGET spdlog)
  find_package(spdlog REQUIRED)
endif()

if(NOT Protobuf_BOUND)
  find_package(Protobuf REQUIRED)
endif()

find_library(UPB_LIBRARIES NAMES upb PATHS ${CMAKE_PREFIX_PATH}/lib)
if(UPB_LIBRARIES)
  add_library(protobuf::libupb STATIC IMPORTED)
  set_target_properties(protobuf::libupb PROPERTIES IMPORTED_LOCATION ${UPB_LIBRARIES})

  add_executable(protobuf::protoc-gen-upb IMPORTED)
  set_target_properties(protobuf::protoc-gen-upb PROPERTIES IMPORTED_LOCATION ${UPB_LIBRARIES})

  add_executable(protobuf::protoc-gen-upbdefs IMPORTED)
  set_target_properties(protobuf::protoc-gen-upbdefs PROPERTIES IMPORTED_LOCATION ${UPB_LIBRARIES})

  add_executable(protobuf::protoc-gen-upb_minitable IMPORTED)
  set_target_properties(protobuf::protoc-gen-upb_minitable PROPERTIES IMPORTED_LOCATION ${UPB_LIBRARIES})
endif()

if(NOT gRPC_FOUND)
  find_package(gRPC REQUIRED)
endif()

if(NOT utf8_range_FOUND)
  find_package(utf8_range REQUIRED)
endif()

function(generate_proto TARGET_NAME PROTO_FILES)
  add_library(${TARGET_NAME} OBJECT ${PROTO_FILES})
  target_include_directories(${TARGET_NAME} PUBLIC ${PROTO_BINARY_DIR})

  protobuf_generate(
    TARGET ${TARGET_NAME}
    IMPORT_DIRS ${PROTO_IMPORT_DIRS}
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
  )

  protobuf_generate(
    TARGET ${TARGET_NAME}
    LANGUAGE grpc
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cpp
    PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC:grpc_cpp_plugin>"
    IMPORT_DIRS ${PROTO_IMPORT_DIRS}
    PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
  )

  target_link_libraries(${TARGET_NAME}
    PUBLIC_HEADER 
      coverage_config
      protobuf::libprotobuf
      gRPC::grpc
      gRPC::grpc++
      utf8_range::utf8_range
      utf8_range::utf8_validity
  )
endfunction()

# generate_proto(abci-proto "somefile.proto")

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${Boost_INCLUDE_DIRS}
)

add_executable(charter src/main.cpp)
target_link_libraries(charter
    coverage_config
)