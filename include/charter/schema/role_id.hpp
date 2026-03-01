#pragma once

#include <charter/schema/enum_string.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

// Schema type: role id.
// Custody workflow: Custody role enum: models operator responsibilities (admin,
// initiator, approver, executor, etc.).
namespace charter::schema {

enum class role_id_t : uint8_t {
  initiator = 0,
  approver = 1,
  executor = 2,
  admin = 3,
  auditor = 4,
  guardian = 5,
  attestor = 6
};

inline constexpr auto kRoleIdMappings = std::array{
    std::pair<std::string_view, role_id_t>{"initiator", role_id_t::initiator},
    std::pair<std::string_view, role_id_t>{"approver", role_id_t::approver},
    std::pair<std::string_view, role_id_t>{"executor", role_id_t::executor},
    std::pair<std::string_view, role_id_t>{"admin", role_id_t::admin},
    std::pair<std::string_view, role_id_t>{"auditor", role_id_t::auditor},
    std::pair<std::string_view, role_id_t>{"guardian", role_id_t::guardian},
    std::pair<std::string_view, role_id_t>{"attestor", role_id_t::attestor},
};

template <>
inline std::optional<role_id_t> try_from_string<role_id_t>(
    const std::string_view value) {
  return from_string(value, kRoleIdMappings);
}

inline constexpr std::string_view to_string(const role_id_t value) {
  return to_string(value, kRoleIdMappings).value_or("unknown");
}

}  // namespace charter::schema
