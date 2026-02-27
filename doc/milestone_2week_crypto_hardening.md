# 2-Week Milestone: Crypto Verification Hardening

Date: 2026-02-27

## Objective
Remove deprecated OpenSSL EC runtime APIs from the signature verification path and keep behavior stable.

## Completed
- Reworked secp256k1 verification in `src/crypto/verify.cpp` to use EVP key construction:
  - `EVP_PKEY_CTX_new_from_name(..., "EC", ...)`
  - `EVP_PKEY_fromdata_init`
  - `EVP_PKEY_fromdata(..., EVP_PKEY_PUBLIC_KEY, ...)`
- Kept ECDSA signature normalization/DER conversion flow intact for current transaction signature format compatibility.
- Removed deprecated EC runtime usage from production verification path:
  - removed `EC_KEY_new_by_curve_name`
  - removed `o2i_ECPublicKey`
  - removed `EC_KEY_free`
  - removed `EVP_PKEY_assign_EC_KEY`
- Updated secp256k1 capability check to EVP-based provider check.

## Validation
- Build: success
- Tests: success (`ctest` passes)

## Notes
- Test code still uses some deprecated OpenSSL helper APIs to generate fixture signatures. This does not affect runtime verification behavior.
- Next hardening step is migrating test fixtures to non-deprecated EVP generation APIs as well.
