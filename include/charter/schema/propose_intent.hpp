#pragma once
#include <charter/schema/primitives.hpp>

namespace charter::schema {

template <uint16_t Version>
struct propose_intent;

template <>
struct propose_intent<1> final {
    const uint16_t version{1};

};

using propose_intent_t = propose_intent<1>;

}