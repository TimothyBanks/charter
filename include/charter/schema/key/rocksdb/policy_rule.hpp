#pragma once
#include <charter/schema/policy_rule.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const policy_rule<1>& o);

}  // namespace charter::schema::key::rocksdb