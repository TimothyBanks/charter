#pragma once
#include <charter/schema/limit_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const limit_rule<1>& o);

}  // namespace charter::schema::key::rocksdb