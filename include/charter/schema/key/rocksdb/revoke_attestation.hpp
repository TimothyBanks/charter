#pragma once
#include <charter/schema/revoke_attestation.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const revoke_attestation<1> &o);

} // namespace charter::schema::key::rocksdb