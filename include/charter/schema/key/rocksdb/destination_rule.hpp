#pragma once
#include <charter/schema/destination_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const destination_rule<1>& o);

}  // namespace charter::schema::key::rocksdb