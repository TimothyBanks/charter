#include <gtest/gtest.h>
#include <charter/abci/server.hpp>

#include <type_traits>

TEST(abci_server_types, listener_is_default_constructible) {
  EXPECT_TRUE((std::is_default_constructible_v<charter::abci::listener>));
}

TEST(abci_server_types, reactor_is_default_constructible) {
  EXPECT_TRUE((std::is_default_constructible_v<charter::abci::reactor>));
}
