#include <charter/schema/key/rocksdb/destination_state.hpp>

using namespace charter::schema;

namespace charter::schema::key::rocksdb {

bytes_t make_key(const upsert_destination<1> &value) { return {}; }

} // namespace charter::schema::key::rocksdb