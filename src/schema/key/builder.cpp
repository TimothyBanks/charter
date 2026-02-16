#include <blake3.h>
#include <algorithm>
#include <charter/schema/key/builder.hpp>
#include <iterator>
#include <ranges>

using namespace charter::schema::key;

builder& builder::write(const std::string_view& str) {
  std::ranges::copy_n(str.data(), str.size(), std::back_inserter(data));
  return *this;
}

builder& builder::write(const std::span<const uint8_t>& bytes) {
  std::ranges::copy_n(bytes.data(), bytes.size(), std::back_inserter(data));
  return *this;
}

builder& builder::write(const signer_id_t& signer_id) {
  std::visit(overloaded{[this](const ed25519_signer_id_t& arg) {
                          this->write(uint8_t{0});
                          this->write(std::span(arg.public_key.data(),
                                                arg.public_key.size()));
                        },
                        [this](const secp256k1_signer_id_t& arg) {
                          this->write(uint8_t{1});
                          this->write(std::span(arg.public_key.data(),
                                                arg.public_key.size()));
                        },
                        [this](const named_signer_t& arg) {
                          this->write(uint8_t{2});
                          this->write(std::span(arg.data(), arg.size()));
                        }},
             signer_id);
  return *this;
}

builder& builder::write(const claim_type_t& claim_type) {
  std::visit(overloaded{[this](const charter::schema::claim_type& arg) {
                          this->write(uint8_t{0});
                          this->write(static_cast<uint16_t>(arg));
                        },
                        [this](const hash32_t& arg) {
                          this->write(uint8_t{1});
                          this->write(std::span(arg.data(), arg.size()));
                        }},
             claim_type);
  return *this;
}

builder& builder::hash(const std::string_view& str) {
  // TODO(tim): Break blake3 out into some sort of RAII type
  auto hasher = blake3_hasher{};
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, str.data(), str.size());
  thread_local uint8_t output[BLAKE3_OUT_LEN];
  blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
  std::ranges::copy_n(output, BLAKE3_OUT_LEN, std::back_inserter(data));
  return *this;
}

builder& builder::hash(const std::span<const uint8_t>& bytes) {
  auto hasher = blake3_hasher{};
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, bytes.data(), bytes.size());
  thread_local uint8_t output[BLAKE3_OUT_LEN];
  blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
  std::ranges::copy_n(output, BLAKE3_OUT_LEN, std::back_inserter(data));
  return *this;
}