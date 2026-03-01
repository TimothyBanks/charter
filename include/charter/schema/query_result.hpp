#pragma once

#include <charter/schema/primitives.hpp>
#include <cstdint>
#include <string>

// Schema type: query result.
// Custody workflow: Read API envelope: returns deterministic query output, key
// echo, height, and error metadata.
namespace charter::schema {

template <uint16_t Version>
struct query_result;

template <>
struct query_result<1> final {
  uint16_t version{1};
  uint32_t code{};
  std::string log;
  std::string info;
  bytes_t key;
  bytes_t value;
  int64_t height{};
  std::string codespace;
};

using query_result_t = query_result<1>;

}  // namespace charter::schema
