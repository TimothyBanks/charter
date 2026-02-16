#include <charter/schema/key/rocksdb/attestation_record.hpp>

using namespace charter::schema;

namespace charter::schema::key::rocksdb {

bytes_t make_key(const attestation_record<1>& value) {
    return {};
}

}