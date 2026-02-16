#include <charter/schema/key/rocksdb/policy_set_state.hpp>

using namespace charter::schema;

namespace charter::schema::key::rocksdb {

bytes_t make_key(const create_policy_set<1>& value) {
    return {};
}

}