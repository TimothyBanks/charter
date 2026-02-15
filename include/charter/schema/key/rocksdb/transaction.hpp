#pragma once
#include <charter/schema/transaction.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const transaction<1>& o);

}  // namespace charter::schema::key::rocksdb