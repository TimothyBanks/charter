#pragma once
#include <charter/schema/cancel_intent.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const cancel_intent<1>& o);

}  // namespace charter::schema::key::rocksdb