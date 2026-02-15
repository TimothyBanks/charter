#pragma once
#include <charter/schema/intent_action.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const intent_action<1> &o);

} // namespace charter::schema::key::rocksdb