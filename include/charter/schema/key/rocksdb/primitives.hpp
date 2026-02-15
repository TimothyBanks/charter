#pragma once
#include <charter/schema/primitives.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const public_key_t &o);
bytes_t make_key(const signature_t &o);
bytes_t make_key(const vault_t &o);
bytes_t make_key(const policy_scope_t &o);

} // namespace charter::schema::key::rocksdb