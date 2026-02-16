#pragma once

#include <charter/schema/chain.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(charter::schema, chain_type,
                             charter::schema::chain_type::bitcoin,
                             charter::schema::chain_type::ethereum,
                             charter::schema::chain_type::solana,
                             charter::schema::chain_type::eosio)