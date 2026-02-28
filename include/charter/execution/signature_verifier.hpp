#pragma once

#include <charter/schema/primitives.hpp>
#include <functional>

namespace charter::execution {

using signature_verifier_t =
    std::function<bool(const charter::schema::bytes_view_t& message,
                       const charter::schema::signer_id_t& signer,
                       const charter::schema::signature_t& signature)>;

}  // namespace charter::execution
