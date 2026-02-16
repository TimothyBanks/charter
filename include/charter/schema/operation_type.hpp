#pragma once
#include <cstdint>

namespace charter::schema {

enum class operation_type_t : uint8_t {
  transfer = 0,
  contract_call = 1,
  raw_sign = 2
};

}