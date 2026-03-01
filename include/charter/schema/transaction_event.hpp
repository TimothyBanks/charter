#pragma once

#include <charter/schema/transaction_event_attribute.hpp>
#include <cstdint>
#include <string>
#include <vector>

// Schema type: transaction event.
// Custody workflow: Event stream item: indexed emission for observability,
// indexing, and post-trade analytics.
namespace charter::schema {

template <uint16_t Version>
struct transaction_event;

template <>
struct transaction_event<1> final {
  uint16_t version{1};
  std::string type;
  std::vector<transaction_event_attribute_t> attributes;
};

using transaction_event_t = transaction_event<1>;

}  // namespace charter::schema
