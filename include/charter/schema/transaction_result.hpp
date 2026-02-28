#pragma once

#include <charter/schema/primitives.hpp>
#include <charter/schema/transaction_event.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace charter::schema {

template <uint16_t Version>
struct transaction_result;

template <>
struct transaction_result<1> final {
  uint16_t version{1};
  uint32_t code{};
  bytes_t data;
  std::string log;
  std::string info;
  int64_t gas_wanted{};
  int64_t gas_used{};
  std::string codespace;
  std::vector<transaction_event_t> events;
};

using transaction_result_t = transaction_result<1>;

}  // namespace charter::schema
