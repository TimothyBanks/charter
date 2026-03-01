cmake_minimum_required(VERSION 3.28.3)

project(charter-custody C CXX)

if(NOT CMAKE_PREFIX_PATH)
 set(CMAKE_PREFIX_PATH "/usr/local")
endif()

# Prefer OpenSSL from CMAKE_PREFIX_PATH by default, while still allowing
# explicit overrides via -DOPENSSL_ROOT_DIR/OPENSSL_*_LIBRARY.
if(NOT DEFINED OPENSSL_ROOT_DIR)
  string(REGEX MATCH "^[^;]+" OPENSSL_ROOT_DIR "${CMAKE_PREFIX_PATH}")
  if(EXISTS "${OPENSSL_ROOT_DIR}")
    set(OPENSSL_ROOT_DIR "${OPENSSL_ROOT_DIR}" CACHE PATH
        "OpenSSL root (defaults to first CMAKE_PREFIX_PATH entry)")
  endif()
endif()
if(DEFINED OPENSSL_ROOT_DIR)
  if(NOT DEFINED OPENSSL_CRYPTO_LIBRARY AND
     EXISTS "${OPENSSL_ROOT_DIR}/lib64/libcrypto.so")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libcrypto.so"
        CACHE FILEPATH "OpenSSL crypto library")
  endif()
  if(NOT DEFINED OPENSSL_SSL_LIBRARY AND
     EXISTS "${OPENSSL_ROOT_DIR}/lib64/libssl.so")
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libssl.so"
        CACHE FILEPATH "OpenSSL SSL library")
  endif()
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -fPIC -DBOOST_LOG_DYN_LINK")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INSTALL_RPATH "${OPENSSL_ROOT_DIR}/lib;${OPENSSL_ROOT_DIR}/lib64;${CMAKE_INSTALL_RPATH};${CMAKE_CURRENT_BINARY_DIR}")
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
option(WITH_PCH "Enable precompiled headers for heavy dependencies" ON)

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
  find_package(Boost 1.90.0 REQUIRED COMPONENTS program_options)
endif()

if(NOT RocksDB_FOUND)
  find_package(RocksDB CONFIG REQUIRED)
endif() 

if(NOT blake3_FOUND)
  find_package(blake3 REQUIRED)
endif()

if(WITH_TESTS AND NOT GTest_FOUND)
  find_package(GTest REQUIRED)
endif()

if(NOT TARGET spdlog)
  find_package(spdlog REQUIRED)
endif()

if(NOT Protobuf_FOUND)
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

if(NOT OpenSSL_FOUND)
  find_package(OpenSSL REQUIRED)
endif()

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CMAKE_CURRENT_LIST_DIR}/src
    ${CMAKE_CURRENT_LIST_DIR}/proto
    ${Boost_INCLUDE_DIRS}
    ${RocksDB_INCLUDE_DIRS}
)

function(generate_proto TARGET_NAME)
  set(PROTO_FILES ${ARGN})
  set(OUT_DIR "${CMAKE_CURRENT_LIST_DIR}/proto/")
  file(MAKE_DIRECTORY "${OUT_DIR}")

  set(PROTO_IMPORT_DIRS
    "${CMAKE_CURRENT_LIST_DIR}/include/charter/abci"
    "${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto"
    "${CMAKE_CURRENT_LIST_DIR}/third_party/gogoproto"
    "${Protobuf_PROTOC_INCLUDE_DIR}"
  )

  add_library(${TARGET_NAME} OBJECT ${PROTO_FILES})
  target_include_directories(${TARGET_NAME} PUBLIC ${OUT_DIR})

  protobuf_generate(
    TARGET ${TARGET_NAME}
    IMPORT_DIRS ${PROTO_IMPORT_DIRS}
    PROTOC_OUT_DIR "${OUT_DIR}"
  )

  protobuf_generate(
    TARGET ${TARGET_NAME}
    LANGUAGE grpc
    GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
    PLUGIN "protoc-gen-grpc=$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
    IMPORT_DIRS ${PROTO_IMPORT_DIRS}
    PROTOC_OUT_DIR "${OUT_DIR}"
  )

  target_link_libraries(${TARGET_NAME}
    PUBLIC
      coverage_config
      protobuf::libprotobuf
      gRPC::grpc
      gRPC::grpc++
      utf8_range::utf8_range
      utf8_range::utf8_validity
  )
endfunction()

generate_proto(health_check "${CMAKE_CURRENT_LIST_DIR}/include/charter/abci/health/health.proto")
generate_proto(gogo_proto "${CMAKE_CURRENT_LIST_DIR}/third_party/gogoproto/gogoproto/gogo.proto")

list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/abci/types.proto)
list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/crypto/keys.proto)
list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/crypto/proof.proto)
list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/types/params.proto)
list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/types/validator.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/blocksync/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/consensus/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/consensus/wal.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/libs/bits/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/mempool/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/p2p/conn.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/p2p/pex.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/p2p/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/privval/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/rpc/grpc/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/state/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/statesync/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/store/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/types/block.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/types/canonical.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/types/events.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/types/evidence.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/types/types.proto)
# list(APPEND ABCI_PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/third_party/cometbft/proto/tendermint/version/types.proto)
message(STATUS ${ABCI_PROTO_FILES})
generate_proto(abci_proto ${ABCI_PROTO_FILES})

set(CHARTER_SCHEMA_SOURCES
  src/schema/primitives.cpp
  src/schema/encoding/scale/activate_policy_set.cpp
  src/schema/encoding/scale/active_policy_pointer.cpp
  src/schema/encoding/scale/apply_destination_update.cpp
  src/schema/encoding/scale/approve_destination_update.cpp
  src/schema/encoding/scale/approval_rule.cpp
  src/schema/encoding/scale/approval_state.cpp
  src/schema/encoding/scale/approve_intent.cpp
  src/schema/encoding/scale/app_info.cpp
  src/schema/encoding/scale/asset_ref.cpp
  src/schema/encoding/scale/asset_state.cpp
  src/schema/encoding/scale/attestation_record.cpp
  src/schema/encoding/scale/block_result.cpp
  src/schema/encoding/scale/cancel_intent.cpp
  src/schema/encoding/scale/claim_requirement.cpp
  src/schema/encoding/scale/commit_result.cpp
  src/schema/encoding/scale/create_policy_set.cpp
  src/schema/encoding/scale/create_vault.cpp
  src/schema/encoding/scale/create_workspace.cpp
  src/schema/encoding/scale/destination_rule.cpp
  src/schema/encoding/scale/destination_update_state.cpp
  src/schema/encoding/scale/disable_asset.cpp
  src/schema/encoding/scale/execute_intent.cpp
  src/schema/encoding/scale/history_entry.cpp
  src/schema/encoding/scale/intent_state.cpp
  src/schema/encoding/scale/jurisdiction.cpp
  src/schema/encoding/scale/limit_rule.cpp
  src/schema/encoding/scale/policy_rule.cpp
  src/schema/encoding/scale/policy_set.cpp
  src/schema/encoding/scale/primitives.cpp
  src/schema/encoding/scale/propose_destination_update.cpp
  src/schema/encoding/scale/propose_intent.cpp
  src/schema/encoding/scale/query_result.cpp
  src/schema/encoding/scale/replay_result.cpp
  src/schema/encoding/scale/revoke_attestation.cpp
  src/schema/encoding/scale/security_event_record.cpp
  src/schema/encoding/scale/set_degraded_mode.cpp
  src/schema/encoding/scale/snapshot_descriptor.cpp
  src/schema/encoding/scale/time_lock_rule.cpp
  src/schema/encoding/scale/transaction.cpp
  src/schema/encoding/scale/transaction_event.cpp
  src/schema/encoding/scale/transaction_event_attribute.cpp
  src/schema/encoding/scale/transaction_result.cpp
  src/schema/encoding/scale/transfer_parameters.cpp
  src/schema/encoding/scale/upsert_attestation.cpp
  src/schema/encoding/scale/upsert_destination.cpp
  src/schema/encoding/scale/upsert_role_assignment.cpp
  src/schema/encoding/scale/upsert_signer_quarantine.cpp
  src/schema/encoding/scale/velocity_counter_state.cpp
  src/schema/encoding/scale/velocity_limit_rule.cpp
)

set(CHARTER_CRYPTO_SOURCES
  src/blake3/hash.cpp
  src/crypto/verify.cpp
)

set(CHARTER_STORAGE_SOURCES
  src/storage/rocksdb/storage.cpp
)

set(CHARTER_EXECUTION_SOURCES
  src/execution/engine.cpp
)

set(CHARTER_ABCI_SOURCES
  src/abci/server.cpp
)

add_library(schema_core STATIC ${CHARTER_SCHEMA_SOURCES})
target_link_libraries(schema_core
  PRIVATE
    coverage_config
    spdlog::spdlog
)
target_compile_definitions(schema_core PRIVATE SPDLOG_USE_STD_FORMAT)
if(WITH_PCH)
  target_precompile_headers(schema_core PRIVATE
    <scale/scale.hpp>
  )
endif()

add_library(crypto_core STATIC ${CHARTER_CRYPTO_SOURCES})
target_link_libraries(crypto_core
  PUBLIC
    BLAKE3::blake3
    OpenSSL::Crypto
    spdlog::spdlog
  PRIVATE
    coverage_config
)
target_compile_definitions(crypto_core PRIVATE SPDLOG_USE_STD_FORMAT)

add_library(storage_core STATIC ${CHARTER_STORAGE_SOURCES})
target_link_libraries(storage_core
  PUBLIC
    schema_core
    RocksDB::rocksdb
    spdlog::spdlog
  PRIVATE
    coverage_config
)
target_compile_definitions(storage_core PRIVATE SPDLOG_USE_STD_FORMAT)
if(WITH_PCH)
  target_precompile_headers(storage_core PRIVATE
    <scale/scale.hpp>
  )
endif()

add_library(execution_core STATIC ${CHARTER_EXECUTION_SOURCES})
target_link_libraries(execution_core
  PUBLIC
    schema_core
    storage_core
    crypto_core
    spdlog::spdlog
  PRIVATE
    coverage_config
)
target_compile_definitions(execution_core PRIVATE SPDLOG_USE_STD_FORMAT)
if(WITH_PCH)
  target_precompile_headers(execution_core PRIVATE
    <scale/scale.hpp>
  )
endif()

add_library(abci_core STATIC ${CHARTER_ABCI_SOURCES})
target_link_libraries(abci_core
  PUBLIC
    execution_core
    abci_proto
    gogo_proto
    health_check
    protobuf::libprotobuf
    gRPC::grpc
    gRPC::grpc++
    gRPC::grpc++_reflection
    utf8_range::utf8_range
    utf8_range::utf8_validity
  PRIVATE
    coverage_config
    spdlog::spdlog
)
target_compile_definitions(abci_core PRIVATE SPDLOG_USE_STD_FORMAT)
add_dependencies(abci_core
  abci_proto
  gogo_proto
  health_check
)

add_executable(charter
  src/main.cpp
)
target_link_libraries(charter
  PRIVATE
    abci_core
    execution_core
    schema_core
    crypto_core
    storage_core
    coverage_config
    ${Boost_LIBRARIES}
    spdlog::spdlog
)
target_compile_definitions(charter PRIVATE SPDLOG_USE_STD_FORMAT)

add_executable(transaction_builder
  src/tools/transaction_builder.cpp
)
target_link_libraries(transaction_builder
  PRIVATE
    schema_core
    crypto_core
    coverage_config
    ${Boost_LIBRARIES}
    spdlog::spdlog
)
target_compile_definitions(transaction_builder PRIVATE SPDLOG_USE_STD_FORMAT)
if(WITH_PCH)
  target_precompile_headers(transaction_builder PRIVATE
    <scale/scale.hpp>
  )
endif()

if(WITH_TESTS)
  enable_testing()
  add_executable(charter_tests
    tests/src/abci/server_types_test.cpp
    tests/src/crypto/verify_test.cpp
    tests/src/execution/engine_integration_test.cpp
    tests/src/execution/engine_types_test.cpp
    tests/src/schema/encoding_types_test.cpp
    tests/src/schema/primitives_test.cpp
    tests/src/schema/transaction_types_test.cpp
    tests/src/storage/storage_types_test.cpp
    tests/src/tools/transaction_builder_test.cpp
  )
  target_link_libraries(charter_tests
    PRIVATE
      abci_core
      execution_core
      schema_core
      crypto_core
      storage_core
      coverage_config
      GTest::gtest
      GTest::gtest_main
      spdlog::spdlog
      ${Boost_LIBRARIES}
  )
  target_include_directories(charter_tests
    PRIVATE
      ${CMAKE_CURRENT_LIST_DIR}/tests/include
  )
  target_compile_definitions(charter_tests
    PRIVATE
      SPDLOG_USE_STD_FORMAT
      CHARTER_TRANSACTION_BUILDER_PATH="$<TARGET_FILE:transaction_builder>"
  )
  add_dependencies(charter_tests transaction_builder)
  if(WITH_PCH)
    target_precompile_headers(charter_tests PRIVATE
      <scale/scale.hpp>
    )
  endif()
  add_test(NAME charter_tests COMMAND charter_tests)
endif()
