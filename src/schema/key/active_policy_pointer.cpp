#include <charter/schema/key/active_policy_pointer.hpp>
#include <charter/schema/key/builder.hpp>

using namespace charter::schema;

namespace charter::schema::key {

bytes_t make_key(const active_policy_pointer<1>& value) {
  return {};
}

}  // namespace charter::schema::key