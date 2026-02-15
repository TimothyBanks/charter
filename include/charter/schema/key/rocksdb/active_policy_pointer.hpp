#pragma once
#include <charter/schema/activate_policy_pointer.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const activate_policy_pointer<1>& o);

}  // namespace charter::schema::key::rocksdb