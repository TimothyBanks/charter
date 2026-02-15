#pragma once
#include <array>
#include <boost/endian/buffers.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>
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

using ed25519_public_key_t = std::array<uint8_t, 32>;
using secp256k1_public_key_t = std::array<uint8_t, 33>;
using named_signer_t = hash32_t;  // On chain identity reference
using public_key_t =
    std::variant<ed25519_public_key_t, secp256k1_public_key_t, named_signer_t>;

using ed25519_signature_t = std::array<uint8_t, 64>;
using secp256k1_signature_t = std::array<uint8_t, 65>;
using signature_t = std::variant<ed25519_signature_t, secp256k1_signature_t>;

using vault_t = std::pair<hash32_t, hash32_t>;  // workspace id, vault id
using policy_scope_t = std::variant<hash32_t, vault_t>;  // workspace id, vault

void encode(public_key_t&& o, scale::Encoder& encoder);
void decode(public_key_t&& o, scale::Decoder& decoder); 

void encode(signature_t&& o, scale::Encoder& encoder);
void decode(signature_t&& o, scale::Decoder& decoder);  

void encode(vault_t&& o, scale::Encoder& encoder);
void decode(vault_t&& o, scale::Decoder& decoder);   

void encode(policy_scope_t&& o, scale::Encoder& encoder);
void decode(policy_scope_t&& o, scale::Decoder& decoder); 

}  // namespace charter::schema