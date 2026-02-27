#include <charter/crypto/verify.hpp>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <array>
#include <optional>
#include <vector>

namespace charter::crypto {

namespace {

bool openssl_has_ed25519() {
  auto* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (ctx == nullptr) {
    return false;
  }
  EVP_PKEY_CTX_free(ctx);
  return true;
}

bool openssl_has_secp256k1() {
  auto* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (ctx == nullptr) {
    return false;
  }
  EVP_PKEY_CTX_free(ctx);
  return true;
}

bool verify_ed25519(const charter::schema::bytes_view_t& message,
                    const charter::schema::ed25519_signer_id& signer,
                    const charter::schema::ed25519_signature_t& signature) {
  auto* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                           signer.public_key.data(),
                                           signer.public_key.size());
  if (pkey == nullptr) {
    return false;
  }

  auto* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    EVP_PKEY_free(pkey);
    return false;
  }

  auto ok = false;
  if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
    ok = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                          message.data(), message.size()) == 1;
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}

std::optional<std::array<uint8_t, 64>> canonical_secp_signature(
    const charter::schema::secp256k1_signature_t& signature) {
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

  auto* key_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  if (key_ctx == nullptr) {
    return false;
  }

  if (EVP_PKEY_fromdata_init(key_ctx) != 1) {
    EVP_PKEY_CTX_free(key_ctx);
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

  auto* pkey = static_cast<EVP_PKEY*>(nullptr);
  if (EVP_PKEY_fromdata(key_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params.data()) !=
      1) {
    EVP_PKEY_CTX_free(key_ctx);
    return false;
  }
  EVP_PKEY_CTX_free(key_ctx);

  auto* ecdsa_sig = ECDSA_SIG_new();
  if (ecdsa_sig == nullptr) {
    EVP_PKEY_free(pkey);
    return false;
  }

  auto* r = BN_bin2bn(compact_signature->data(), 32, nullptr);
  auto* s = BN_bin2bn(compact_signature->data() + 32, 32, nullptr);
  if (r == nullptr || s == nullptr || ECDSA_SIG_set0(ecdsa_sig, r, s) != 1) {
    if (r != nullptr) {
      BN_free(r);
    }
    if (s != nullptr) {
      BN_free(s);
    }
    ECDSA_SIG_free(ecdsa_sig);
    EVP_PKEY_free(pkey);
    return false;
  }

  auto der_len = i2d_ECDSA_SIG(ecdsa_sig, nullptr);
  if (der_len <= 0) {
    ECDSA_SIG_free(ecdsa_sig);
    EVP_PKEY_free(pkey);
    return false;
  }
  auto der = std::vector<uint8_t>(static_cast<size_t>(der_len));
  auto* der_ptr = der.data();
  i2d_ECDSA_SIG(ecdsa_sig, &der_ptr);

  auto* ctx = EVP_MD_CTX_new();
  if (ctx == nullptr) {
    EVP_PKEY_free(pkey);
    ECDSA_SIG_free(ecdsa_sig);
    return false;
  }

  auto ok = false;
  if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
    ok = EVP_DigestVerify(ctx, der.data(), der.size(), message.data(),
                          message.size()) == 1;
  }

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  ECDSA_SIG_free(ecdsa_sig);
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
