#pragma once
#include <cstdint>

namespace charter::schema {

enum class asset_kind_t : uint8_t {
  native = 0,
  erc20 = 1,
  erc721 = 2,
  erc1115 = 3,
  other = 4
};

}