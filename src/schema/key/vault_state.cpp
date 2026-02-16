#include <charter/schema/key/builder.hpp>
#include <charter/schema/key/vault_state.hpp>

using namespace charter::schema;

namespace charter::schema::key {

bytes_t make_key(const create_vault<1>& value) {
  auto b = builder{};
  b.write("VAULTSTATE|");
  b.write(std::span(value.workspace_id.data(), value.workspace_id.size()));
  b.write("|");
  b.write(std::span(value.vault_id.data(), value.vault_id.size()));
  return b.data;
}

}  // namespace charter::schema::key