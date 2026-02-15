#pragma once
#include <charter/schema/vault_model.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>
#include <sys/types.h>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const vault_model_t &o);

} // namespace charter::schema::key::rocksdb