#include <charter/schema/key/rocksdb/intent_state.hpp>

using namespace charter::schema;

namespace charter::schema::key::rocksdb {

bytes_t make_key(const intent_state<1> &value) { return {}; }

} // namespace charter::schema::key::rocksdb