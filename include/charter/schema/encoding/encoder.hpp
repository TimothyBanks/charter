#pragma once
#include <charter/schema/primitives.hpp>
#include <span>

namespace charter::charter::schema::encoding {

template <typename EncoderLibrary>
struct encoder {
  template <typename T>
  charter::schema::bytes_t encode(const T& obj);

  template <typename T>
  void encode(const T& obj, charter::schema::bytes_t& out);

  template <typename T>
  T decode(const std::span<uint8_t>& bytes);
};

}  // namespace charter::charter::schema::encoding