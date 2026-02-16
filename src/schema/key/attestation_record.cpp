#include <charter/schema/key/attestation_record.hpp>
#include <charter/schema/key/builder.hpp>

using namespace charter::schema;

namespace charter::schema::key {

bytes_t make_key(const attestation_record<1>& value) {
  auto b = builder{};
  b.write("ATTESTATIONRECORD|");
  b.write(std::span(value.workspace_id.data(), value.workspace_id.size()));
  b.write("|");
  b.write(std::span(value.subject.data(), value.subject.size()));
  b.write("|");
  b.write(value.claim);
  b.write("|");
  b.write(value.issuer);
  return b.data;
}

}  // namespace charter::schema::key