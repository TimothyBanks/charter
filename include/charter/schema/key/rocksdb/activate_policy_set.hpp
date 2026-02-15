#pragma once
#include <charter/schema/activate_policy_set.hpp>

namespace charter::schema::key::rocksdb {

bytes_t make_key(const activate_policy_set<1> &o);

} // namespace charter::schema::key::rocksdb