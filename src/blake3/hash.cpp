#include <blake3.h>
#include <charter/blake3/hash.hpp>
#include <iterator>
#include <ranges>

namespace charter::blake3 {

charter::schema::bytes_t hash(const std::string_view& str) {
  // TODO(tim): Break blake3 out into some sort of RAII type
  auto hasher = blake3_hasher{};
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, str.data(), str.size());
  auto output = charter::schema::bytes_t(BLAKE3_OUT_LEN);
  blake3_hasher_finalize(&hasher, output.data(), output.size());
  return output;
}

charter::schema::bytes_t hash(const std::span<const uint8_t>& bytes) {
  auto hasher = blake3_hasher{};
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, bytes.data(), bytes.size());
  auto output = charter::schema::bytes_t(BLAKE3_OUT_LEN);
  blake3_hasher_finalize(&hasher, output.data(), output.size());
  return output;
}

}  // namespace charter::blake3