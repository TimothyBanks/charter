#pragma once
#include <array>
#include <boost/endian/buffers.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>
#include <variant>
#include <vector>

namespace charter::schema {

using bytes_t = std::vector<uint8_t>;
using hash32_t = std::array<uint8_t, 32>;
using account_id_t = hash32_t;
using asset_id_t = hash32_t;
using amount_t = boost::multiprecision::uint256_t;
using timestamp_milliseconds_t = uint64_t;
using duration_milliseconds_t = uint64_t;

struct ed25519_signer_id_t final {
  std::array<uint8_t, 32> public_key;
};

struct secp256k1_signer_id_t final {
  std::array<uint8_t, 33> public_key;
};

using named_signer_t = hash32_t;  // On chain identity reference
using signer_id_t =
    std::variant<ed25519_signer_id_t, secp256k1_signer_id_t, named_signer_t>;

using ed25519_signature_t = std::array<uint8_t, 64>;
using secp256k1_signature_t = std::array<uint8_t, 65>;
using signature_t = std::variant<ed25519_signature_t, secp256k1_signature_t>;

using vault_t = std::pair<hash32_t, hash32_t>;  // workspace id, vault id
using policy_scope_t = std::variant<hash32_t, vault_t>;  // workspace id, vault

}  // namespace charter::schema

template <class... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;