#pragma once
#include <charter/schema/primitives.hpp>
#include <variant>

namespace charter::schema {

enum class chain_type : uint16_t {
  bitcoin = 0,
  ethereum = 1,
  solana = 2,
  eosio = 3,
};

// bytes - user defined identifier
using chain_type_t = std::variant<chain_type, bytes_t>;

} // namespace charter::schema