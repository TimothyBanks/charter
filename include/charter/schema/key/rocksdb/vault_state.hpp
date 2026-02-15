#pragma once
#include <charter/schema/vault_state.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const vault_state<1>& o);

}  // namespace charter::schema::key::rocksdb