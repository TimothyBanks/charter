#pragma once
#include <sys/types.h>
#include <charter/schema/vault_model.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const vault_model_t& o);

}  // namespace charter::schema::key::rocksdb