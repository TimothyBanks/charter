#pragma once

#include <array>
#include <optional>
#include <string_view>
#include <utility>

namespace charter::schema {

template <typename Enum, std::size_t N>
constexpr std::optional<Enum> from_string(
    const std::string_view value,
    const std::array<std::pair<std::string_view, Enum>, N>& mappings) {
  for (const auto& [name, enum_value] : mappings) {
    if (name == value) {
      return enum_value;
    }
  }
  return std::nullopt;
}

template <typename Enum, std::size_t N>
constexpr std::optional<std::string_view> to_string(
    const Enum value,
    const std::array<std::pair<std::string_view, Enum>, N>& mappings) {
  for (const auto& [name, enum_value] : mappings) {
    if (enum_value == value) {
      return name;
    }
  }
  return std::nullopt;
}

template <typename Enum>
std::optional<Enum> try_from_string(const std::string_view value) {
  static_cast<void>(value);
  return std::nullopt;
}

}  // namespace charter::schema
