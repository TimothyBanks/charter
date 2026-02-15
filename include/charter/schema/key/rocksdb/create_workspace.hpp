#pragma once
#include <charter/schema/create_workspace.hpp>
#include <scale/decoder.hpp>
#include <scale/encoder.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const create_workspace<1>& o);

}  // namespace charter::schema::key::rocksdb