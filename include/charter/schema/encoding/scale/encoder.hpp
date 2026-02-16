#pragma once
#include <scale/scale.hpp>

namespace charter::charter::schema::encoding::scale {

template <>
struct encoder<::scale::encoder> final {
  template <typename T>
  charter::schema::bytes_t encode(const T& obj);

  template <typename T>
  T decode(const std::span<uint8_t>& bytes);
};

template <>
template <typename T>
charter::schema::bytes_t encoder<::scale::encoder>::encode(const T& obj) {
  auto encoder = ::scale::encoder{};
  encoder << obj;
  return encoder.data();
}

template <>
template <typename T>
T encoder<::scale::encoder>::decode(const std::span<uint8_t>& bytes) {
  auto decoder = ::scale::decoder{bytes};
  T obj;
  decoder >> obj;
  return obj;
}

}  // namespace charter::charter::schema::encoding::scale