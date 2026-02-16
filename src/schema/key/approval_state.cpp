#include <charter/schema/key/approval_state.hpp>
#include <charter/schema/key/builder.hpp>

using namespace charter::schema;

namespace charter::schema::key {

bytes_t make_key(const approval_state<1>& value) {
  auto b = builder{};
  b.write("APPROVALSTATE|");
  b.write(std::span(value.intent_id.data(), value.intent_id.size()));
  b.write("|");
  b.write(value.signer);
  return b.data;
}

}  // namespace charter::schema::key