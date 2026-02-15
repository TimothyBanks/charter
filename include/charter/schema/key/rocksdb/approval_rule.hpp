#pragma once
#include <charter/schema/approval_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const approval_rule<1>& o);

}  // namespace charter::schema::key::rocksdb