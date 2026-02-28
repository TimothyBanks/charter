#include <charter/crypto/verify.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <array>
#include <memory>
#include <optional>
#include <vector>

namespace charter::crypto {

namespace {

using evp_pkey_ctx_ptr =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using evp_pkey_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using evp_md_ctx_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using ecdsa_sig_ptr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;
using bignum_ptr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

bool openssl_has_ed25519() {
  auto ctx = evp_pkey_ctx_ptr{EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr),
                              EVP_PKEY_CTX_free};
  if (!ctx) {
    return false;
  }
  return true;
}

bool openssl_has_secp256k1() {
  auto ctx = evp_pkey_ctx_ptr{
      EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free};
  if (!ctx) {
    return false;
  }
  return true;
}

bool verify_ed25519(const charter::schema::bytes_view_t& message,
                    const charter::schema::ed25519_signer_id& signer,
                    const charter::schema::ed25519_signature_t& signature) {
  auto pkey =
      evp_pkey_ptr{EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                               signer.public_key.data(),
                                               signer.public_key.size()),
                   EVP_PKEY_free};
  if (!pkey) {
    return false;
  }

  auto ctx = evp_md_ctx_ptr{EVP_MD_CTX_new(), EVP_MD_CTX_free};
  if (!ctx) {
    return false;
  }

  auto ok = false;
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) ==
      1) {
    ok = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                          message.data(), message.size()) == 1;
  }
  return ok;
}

std::optional<std::array<uint8_t, 64>> canonical_secp_signature(
    const charter::schema::secp256k1_signature_t& signature) {
  // Charter accepts both common 65-byte secp256k1 encodings:
  // - [v || r || s] where the first byte is a recovery id
  // - [r || s || v] where the last byte is a recovery id
  // We detect which side carries v and return canonical compact [r || s].
  // Recovery ids are accepted as small values (0..3) and legacy Ethereum
  // style values (27+); values in 4..26 are treated as invalid.
  auto out = std::array<uint8_t, 64>{};
  if (signature[0] <= 3 || signature[0] >= 27) {
    std::copy_n(signature.data() + 1, out.size(), out.data());
    return out;
  }
  if (signature[64] <= 3 || signature[64] >= 27) {
    std::copy_n(signature.data(), out.size(), out.data());
    return out;
  }
  return std::nullopt;
}

bool verify_secp256k1(const charter::schema::bytes_view_t& message,
                      const charter::schema::secp256k1_signer_id& signer,
                      const charter::schema::secp256k1_signature_t& signature) {
  auto compact_signature = canonical_secp_signature(signature);
  if (!compact_signature.has_value()) {
    return false;
  }

  auto key_ctx = evp_pkey_ctx_ptr{
      EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free};
  if (!key_ctx) {
    return false;
  }

  if (EVP_PKEY_fromdata_init(key_ctx.get()) != 1) {
    return false;
  }

  auto* group_name = const_cast<char*>("secp256k1");
  auto params =
      std::array{OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                  group_name, 0),
                 OSSL_PARAM_construct_octet_string(
                     OSSL_PKEY_PARAM_PUB_KEY,
                     const_cast<unsigned char*>(signer.public_key.data()),
                     signer.public_key.size()),
                 OSSL_PARAM_construct_end()};

  auto* raw_pkey = static_cast<EVP_PKEY*>(nullptr);
  if (EVP_PKEY_fromdata(key_ctx.get(), &raw_pkey, EVP_PKEY_PUBLIC_KEY,
                        params.data()) != 1) {
    return false;
  }
  auto pkey = evp_pkey_ptr{raw_pkey, EVP_PKEY_free};

  auto ecdsa_sig = ecdsa_sig_ptr{ECDSA_SIG_new(), ECDSA_SIG_free};
  if (!ecdsa_sig) {
    return false;
  }

  auto r =
      bignum_ptr{BN_bin2bn(compact_signature->data(), 32, nullptr), BN_free};
  auto s = bignum_ptr{BN_bin2bn(compact_signature->data() + 32, 32, nullptr),
                      BN_free};
  if (!r || !s ||
      ECDSA_SIG_set0(ecdsa_sig.get(), r.release(), s.release()) != 1) {
    return false;
  }

  auto der_len = i2d_ECDSA_SIG(ecdsa_sig.get(), nullptr);
  if (der_len <= 0) {
    return false;
  }
  auto der = std::vector<uint8_t>(static_cast<size_t>(der_len));
  auto* der_ptr = der.data();
  i2d_ECDSA_SIG(ecdsa_sig.get(), &der_ptr);

  auto ctx = evp_md_ctx_ptr{EVP_MD_CTX_new(), EVP_MD_CTX_free};
  if (!ctx) {
    return false;
  }

  auto ok = false;
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr,
                           pkey.get()) == 1) {
    ok = EVP_DigestVerify(ctx.get(), der.data(), der.size(), message.data(),
                          message.size()) == 1;
  }
  return ok;
}

}  // namespace

bool available() {
  static const auto available_now =
      openssl_has_ed25519() && openssl_has_secp256k1();
  return available_now;
}

bool verify_signature(const charter::schema::bytes_view_t& message,
                      const charter::schema::signer_id_t& signer,
                      const charter::schema::signature_t& signature) {
  auto verified = false;
  std::visit(
      overloaded{
          [&](const charter::schema::ed25519_signer_id& value) {
            if (!std::holds_alternative<charter::schema::ed25519_signature_t>(
                    signature)) {
              verified = false;
              return;
            }
            verified = verify_ed25519(
                message, value,
                std::get<charter::schema::ed25519_signature_t>(signature));
          },
          [&](const charter::schema::secp256k1_signer_id& value) {
            if (!std::holds_alternative<charter::schema::secp256k1_signature_t>(
                    signature)) {
              verified = false;
              return;
            }
            verified = verify_secp256k1(
                message, value,
                std::get<charter::schema::secp256k1_signature_t>(signature));
          },
          [&](const charter::schema::named_signer_t&) { verified = false; }},
      signer);
  return verified;
}

}  // namespace charter::crypto
