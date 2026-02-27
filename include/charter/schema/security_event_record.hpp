#pragma once

#include <charter/schema/primitives.hpp>
#include <charter/schema/security_event_severity.hpp>
#include <charter/schema/security_event_type.hpp>
#include <optional>

namespace charter::schema {

template <uint16_t Version>
struct security_event_record;

template <>
struct security_event_record<1> final {
  uint16_t version{1};
  uint64_t event_id{};
  uint64_t height{};
  uint32_t tx_index{};
  security_event_type_t type{};
  security_event_severity_t severity{};
  uint32_t code{};
  bytes_t message;
  std::optional<signer_id_t> signer;
  std::optional<hash32_t> workspace_id;
  std::optional<hash32_t> vault_id;
  timestamp_milliseconds_t recorded_at{};
};

using security_event_record_t = security_event_record<1>;

}  // namespace charter::schema
