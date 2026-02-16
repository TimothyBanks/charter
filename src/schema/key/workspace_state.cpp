#include <charter/schema/key/builder.hpp>
#include <charter/schema/key/workspace_state.hpp>

using namespace charter::schema;

namespace charter::schema::key {

bytes_t make_key(const create_workspace<1>& value) {
  auto b = builder{};
  b.write("WORKSPACESTATE|");
  b.write(std::span(value.workspace_id.data(), value.workspace_id.size()));
  return b.data;
}

}  // namespace charter::schema::key