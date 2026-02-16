#pragma once
#include <charter/schema/upsert_destination.hpp>

namespace charter::schema::key::rocksdb {

charter::schema::bytes_t
make_key(const charter::schema::upsert_destination<1> &value);

}