#pragma once
#include <charter/schema/approval_state.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const approval_state<1> &o);

} // namespace charter::schema::key::rocksdb