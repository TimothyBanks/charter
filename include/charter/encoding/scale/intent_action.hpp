#pragma once
#include <charter/schema/transfer_parameters.hpp>
#include <variant>

namespace charter::schema {

using intent_action_t = std::variant<transfer_parameters_t>;

}