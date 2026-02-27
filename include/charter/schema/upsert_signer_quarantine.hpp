#pragma once

#include <charter/schema/primitives.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct upsert_signer_quarantine;

template <>
struct upsert_signer_quarantine<1> final {
  uint16_t version{1};
  signer_id_t signer;
  bool quarantined{true};
  std::optional<timestamp_milliseconds_t> until;
  std::optional<bytes_t> reason;
};

using upsert_signer_quarantine_t = upsert_signer_quarantine<1>;
using signer_quarantine_state_t = upsert_signer_quarantine<1>;

}  // namespace charter::schema
