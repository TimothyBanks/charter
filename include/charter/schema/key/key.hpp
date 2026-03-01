#pragma once
#include <charter/schema/primitives.hpp>

// Schema key type: key.
// Custody workflow: Shared key helper utilities for deterministic key
// construction and parsing.
namespace charter::schema::key {

template <typename Encoder, typename... Args>
charter::schema::bytes_t make_key(Encoder& encoder,
                                  const std::string_view& prefix,
                                  const Args&... args) {
  thread_local auto output = charter::schema::bytes_t{};
  encoder.encode(prefix, output);
  auto enc = [&]<typename T>(const T& arg) {
    encoder.encode(arg, output);
    encoder.encode("|", output);
  };
  (enc(args), ...);
  return output;
}

}  // namespace charter::schema::key
