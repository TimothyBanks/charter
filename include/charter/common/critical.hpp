#pragma once

#include <csignal>
#include <exception>
#include <string_view>

#include <spdlog/spdlog.h>

namespace charter::common {

[[noreturn]] inline void critical(const std::string_view message) {
  spdlog::critical("{}", message);
  spdlog::shutdown();
  std::raise(SIGTERM);
  std::terminate();
}

}  // namespace charter::common
