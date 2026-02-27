#include <charter/crypto/verify.hpp>
#include <gtest/gtest.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <array>
#include <vector>

TEST(crypto_verify, verifies_ed25519_signatures) {
  if (!charter::crypto::available()) {
    GTEST_SKIP() << "OpenSSL backend does not expose required crypto providers";
  }
  auto *keygen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  ASSERT_NE(keygen_ctx, nullptr);
  ASSERT_EQ(EVP_PKEY_keygen_init(keygen_ctx), 1);
  auto *pkey = static_cast<EVP_PKEY *>(nullptr);
  ASSERT_EQ(EVP_PKEY_keygen(keygen_ctx, &pkey), 1);
  EVP_PKEY_CTX_free(keygen_ctx);

  auto public_key = std::array<uint8_t, 32>{};
  auto public_key_size = public_key.size();
  ASSERT_EQ(
      EVP_PKEY_get_raw_public_key(pkey, public_key.data(), &public_key_size),
      1);
  ASSERT_EQ(public_key_size, public_key.size());

  auto message = std::vector<uint8_t>{'c', 'h', 'a', 'r', 't', 'e', 'r'};
  auto signature = std::array<uint8_t, 64>{};
  auto signature_size = signature.size();
  auto *sign_ctx = EVP_MD_CTX_new();
  ASSERT_NE(sign_ctx, nullptr);
  ASSERT_EQ(EVP_DigestSignInit(sign_ctx, nullptr, nullptr, nullptr, pkey), 1);
  ASSERT_EQ(EVP_DigestSign(sign_ctx, signature.data(), &signature_size,
                           message.data(), message.size()),
            1);
  EVP_MD_CTX_free(sign_ctx);
  ASSERT_EQ(signature_size, signature.size());

  auto signer = charter::schema::ed25519_signer_id{.public_key = public_key};
  auto signer_variant = charter::schema::signer_id_t{signer};
  auto signature_variant = charter::schema::signature_t{signature};
  auto ok = charter::crypto::verify_signature(
      charter::schema::bytes_view_t{message.data(), message.size()},
      signer_variant, signature_variant);
  EXPECT_TRUE(ok);

  EVP_PKEY_free(pkey);
}

TEST(crypto_verify, verifies_secp256k1_signatures) {
  if (!charter::crypto::available()) {
    GTEST_SKIP() << "OpenSSL backend does not expose required crypto providers";
  }
  auto *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  ASSERT_NE(ec_key, nullptr);
  ASSERT_EQ(EC_KEY_generate_key(ec_key), 1);
  EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);

  auto compressed = std::array<uint8_t, 33>{};
  auto *pub_ptr = compressed.data();
  auto pub_len = i2o_ECPublicKey(ec_key, &pub_ptr);
  ASSERT_EQ(pub_len, static_cast<long>(compressed.size()));

  auto *pkey = EVP_PKEY_new();
  ASSERT_NE(pkey, nullptr);
  ASSERT_EQ(EVP_PKEY_assign_EC_KEY(pkey, ec_key), 1);

  auto message = std::vector<uint8_t>{'s', 'e', 'c', 'p', '-', 'm', 's', 'g'};
  auto *sign_ctx = EVP_MD_CTX_new();
  ASSERT_NE(sign_ctx, nullptr);
  ASSERT_EQ(EVP_DigestSignInit(sign_ctx, nullptr, EVP_sha256(), nullptr, pkey),
            1);
  auto der_size = size_t{};
  ASSERT_EQ(EVP_DigestSign(sign_ctx, nullptr, &der_size, message.data(),
                           message.size()),
            1);
  auto der = std::vector<uint8_t>(der_size);
  ASSERT_EQ(EVP_DigestSign(sign_ctx, der.data(), &der_size, message.data(),
                           message.size()),
            1);
  EVP_MD_CTX_free(sign_ctx);

  auto *der_ptr = der.data();
  auto *sig =
      d2i_ECDSA_SIG(nullptr, const_cast<const unsigned char **>(&der_ptr),
                    static_cast<long>(der_size));
  ASSERT_NE(sig, nullptr);
  const auto *r = static_cast<const BIGNUM *>(nullptr);
  const auto *s = static_cast<const BIGNUM *>(nullptr);
  ECDSA_SIG_get0(sig, &r, &s);

  auto compact = charter::schema::secp256k1_signature_t{};
  compact[0] = 0;
  ASSERT_EQ(BN_bn2binpad(r, compact.data() + 1, 32), 32);
  ASSERT_EQ(BN_bn2binpad(s, compact.data() + 33, 32), 32);
  ECDSA_SIG_free(sig);

  auto signer = charter::schema::secp256k1_signer_id{.public_key = compressed};
  auto ok = charter::crypto::verify_signature(
      charter::schema::bytes_view_t{message.data(), message.size()},
      charter::schema::signer_id_t{signer},
      charter::schema::signature_t{compact});
  EXPECT_TRUE(ok);

  EVP_PKEY_free(pkey);
}
