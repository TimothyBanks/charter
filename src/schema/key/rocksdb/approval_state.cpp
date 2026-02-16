#include <charter/schema/key/rocksdb/approval_state.hpp>

using namespace charter::schema;

namespace charter::schema::key::rocksdb {

bytes_t make_key(const approval_state<1>& value) {
    return {};
}

}