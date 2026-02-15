#pragma once
#include <charter/schema/chain.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const chain_type_t& o);

}  // namespace charter::schema::key::rocksdb