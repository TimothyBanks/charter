#pragma once
#include <charter/schema/attestation_record.hpp>

namespace charter::schema::key::rocksdb {
    
charter::schema::bytes_t make_key(const charter::schema::attestation_record<1>& value);

}