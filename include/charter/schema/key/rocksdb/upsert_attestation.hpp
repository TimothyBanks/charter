#pragma once
#include <charter/schema/upsert_attestation.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const upsert_attestation<1> &o);

} // namespace charter::schema::key::rocksdb