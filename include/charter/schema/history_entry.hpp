#pragma once

#include <charter/schema/primitives.hpp>
#include <cstdint>

namespace charter::schema {

template <uint16_t Version>
struct history_entry;

template <>
struct history_entry<1> final {
  uint16_t version{1};
  uint64_t height{};
  uint32_t index{};
  uint32_t code{};
  bytes_t tx;
};

using history_entry_t = history_entry<1>;

}  // namespace charter::schema
