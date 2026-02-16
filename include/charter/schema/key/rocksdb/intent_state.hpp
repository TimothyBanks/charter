#pragma once
#include <charter/schema/intent_state.hpp>

namespace charter::schema::key::rocksdb {

charter::schema::bytes_t
make_key(const charter::schema::intent_state<1> &value);

}