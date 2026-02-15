#pragma once
#include <charter/schema/transfer_parameters.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const transfer_parameters<1>& o);

}  // namespace charter::schema::key::rocksdb