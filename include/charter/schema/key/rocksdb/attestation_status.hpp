#pragma once
#include <charter/schema/attestation_status.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const attestation_status<1>& o);

}  // namespace charter::schema::key::rocksdb