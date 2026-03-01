#pragma once

#include <cstdint>
#include <string>

// Schema type: transaction event attribute.
// Custody workflow: Event attribute tuple: key/value/index metadata used by
// event consumers.
namespace charter::schema {

template <uint16_t Version>
struct transaction_event_attribute;

template <>
struct transaction_event_attribute<1> final {
  uint16_t version{1};
  std::string key;
  std::string value;
  bool index{};
};

using transaction_event_attribute_t = transaction_event_attribute<1>;

}  // namespace charter::schema
