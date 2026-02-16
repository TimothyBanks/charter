#include <charter/schema/key/builder.hpp>
#include <charter/schema/key/nonce_record.hpp>

using namespace charter::schema;

namespace charter::schema::key {

bytes_t make_key(const signer_id_t& value) {
  auto b = builder{};
  b.write("NONCE|");
  b.write(value);
  return b.data;
}

}  // namespace charter::schema::key