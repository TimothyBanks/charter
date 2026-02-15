#pragma once
#include <charter/schema/intent_status.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const intent_status_t& o);

}  // namespace charter::schema::key::rocksdb