#pragma once
#include <array>
#include <boost/endian/buffers.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace charter::schema {

using bytes_t = std::vector<uint8_t>;
using bytes_view_t = std::span<const uint8_t>;
using hash32_t = std::array<uint8_t, 32>;
using has32_view_t = std::span<const uint8_t>;
using account_id_t = hash32_t;
using asset_id_t = hash32_t;
using amount_t = boost::multiprecision::uint256_t;
using timestamp_milliseconds_t = uint64_t;
using duration_milliseconds_t = uint64_t;

bytes_t make_bytes(const bytes_view_t& bytes);
bytes_t make_bytes(const std::string& bytes);
bytes_t make_bytes(const std::string_view& bytes);

bytes_view_t make_bytes_view(const bytes_t& bytes);
bytes_view_t make_bytes_view(const std::string& bytes);
bytes_view_t make_bytes_view(const std::string_view& bytes);

std::string_view make_string_view(const bytes_t& bytes);
std::string_view make_string_view(const bytes_view_t& bytes);
std::string make_string(const bytes_t& bytes);
std::string make_string(const bytes_view_t& bytes);

hash32_t make_hash32(const bytes_t& bytes);
hash32_t make_hash32(const std::string& bytes);
hash32_t make_hash32(const std::string_view& bytes);
std::optional<hash32_t> try_make_hash32(const std::string& bytes);
std::optional<hash32_t> try_make_hash32(const std::string_view& bytes);
hash32_t make_zero_hash();

struct ed25519_signer_id final {
  std::array<uint8_t, 32> public_key;
};

struct secp256k1_signer_id final {
  std::array<uint8_t, 33> public_key;
};

using named_signer_t = hash32_t;  // On chain identity reference
using signer_id_t =
    std::variant<ed25519_signer_id, secp256k1_signer_id, named_signer_t>;

using ed25519_signature_t = std::array<uint8_t, 64>;
using secp256k1_signature_t = std::array<uint8_t, 65>;
using signature_t = std::variant<ed25519_signature_t, secp256k1_signature_t>;

struct vault_t final {
  hash32_t workspace_id{};
  hash32_t vault_id{};
};
struct workspace_scope_t final {
  hash32_t workspace_id{};
};
using policy_scope_t = std::variant<workspace_scope_t, vault_t>;

}  // namespace charter::schema

template <class... Ts>
struct overloaded : Ts... {
  using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;
