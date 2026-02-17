#pragma once
#include <charter/schema/primitives.hpp>
#include <optional>

namespace charter::storage {

template <typename Library>
struct storage {
  template <typename Encoder, typename T>
  std::optional<T> get(Encoder& encoder, const charter::schema::bytes_t& key);

  template <typename Encoder, typename T>
  void put(Encoder& encoder, T value);
};

template <typename Library>
storage<Library> make_storage(const std::string_view& path);

}  // namespace charter::storage