#pragma once

#include <charter/schema/create_workspace.hpp>
#include <charter/testing/execution_harness.hpp>

#include <cstdint>
#include <optional>

namespace charter::testing {

inline charter::schema::transaction_t make_create_workspace_transaction(
    const charter::schema::hash32_t& chain_id,
    const uint64_t nonce,
    const charter::schema::signer_id_t& signer,
    const charter::schema::hash32_t& workspace_id) {
  return make_transaction(
      chain_id, nonce, signer,
      charter::schema::create_workspace_t{.workspace_id = workspace_id,
                                          .admin_set = {signer},
                                          .quorum_size = 1,
                                          .metadata_ref = std::nullopt});
}

}  // namespace charter::testing
