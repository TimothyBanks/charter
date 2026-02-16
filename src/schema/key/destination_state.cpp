#include <charter/schema/key/builder.hpp>
#include <charter/schema/key/destination_state.hpp>

using namespace charter::schema;

namespace charter::schema::key {

bytes_t make_key(const upsert_destination<1>& value) {
  auto b = builder{};
  b.write("DESTINATIONSTATE|");
  b.write(std::span(value.workspace_id.data(), value.workspace_id.size()));
  b.write("|");
  b.write(std::span(value.destination_id.data(), value.destination_id.size()));
  return b.data;
}

}  // namespace charter::schema::key