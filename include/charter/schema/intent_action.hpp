#pragma once
#include <charter/schema/transfer_parameters.hpp>
#include <variant>

// Schema type: intent action.
// Custody workflow: Action variant envelope: allows intent workflow evolution
// beyond transfer-only actions.
namespace charter::schema {

using intent_action_t = std::variant<transfer_parameters_t>;

}
