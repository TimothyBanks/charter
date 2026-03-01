#pragma once
#include <charter/schema/jurisdiction.hpp>
#include <charter/schema/primitives.hpp>
#include <charter/schema/vault_model.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct create_vault;

template <>
struct create_vault<1> final {
  uint16_t version{1};
  hash32_t workspace_id;
  hash32_t vault_id;
  vault_model_t model{};
  std::optional<bytes_t> label;
  std::optional<jurisdiction_t> jurisdiction{std::nullopt};
};

using create_vault_t = create_vault<1>;
using vault_state_t = create_vault<1>;

}  // namespace charter::schema
