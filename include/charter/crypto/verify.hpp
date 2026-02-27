#pragma once

#include <charter/schema/primitives.hpp>

namespace charter::crypto {

bool available();

bool verify_signature(const charter::schema::bytes_view_t& message,
                      const charter::schema::signer_id_t& signer,
                      const charter::schema::signature_t& signature);

}  // namespace charter::crypto
