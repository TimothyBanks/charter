#include <charter/abci/server.hpp>
#include <gtest/gtest.h>

#include <type_traits>

TEST(abci_server_types, listener_is_default_constructible) {
  EXPECT_TRUE((std::is_default_constructible_v<charter::abci::listener>));
}

TEST(abci_server_types, reactor_is_default_constructible) {
  EXPECT_TRUE((std::is_default_constructible_v<charter::abci::reactor>));
}

TEST(abci_server_types, listener_backup_api_is_exposed) {
  using listener_t = charter::abci::listener;
  EXPECT_TRUE((std::is_member_function_pointer_v<decltype(&listener_t::load_backup)>));
  EXPECT_TRUE((std::is_member_function_pointer_v<decltype(&listener_t::persist_backup)>));
  EXPECT_TRUE((std::is_member_function_pointer_v<decltype(&listener_t::replay_history)>));
}
