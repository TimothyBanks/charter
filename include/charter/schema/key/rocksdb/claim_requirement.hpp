#pragma once
#include <charter/schema/claim_requirement.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const claim_requirement<1>& o);

}  // namespace charter::schema::key::rocksdb