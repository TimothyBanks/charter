#pragma once
#include <charter/schema/primitives.hpp>
#include <optional>
#include <span>

namespace charter::schema::encoding {

// TODO(tim): I do not like this encoder design.
// I should make it a erased type and provide
// some sort of registry to register things like
// 1. Which encoder to use
// 2. Which storage backend to use
// 3. Which schema version to use.
// 4. Which hash library (maybe)
// 5. etc.
// This would apply to all these abstractions to
// hide which implementation api is being used.
// That is, for instance, using SCALE or
// some custom encoder.  Using LevelDB, RocksDB
// or some custom storage solution.  Using Blake2, Keccak256
// or some custom hashing solution.  This would allow
// us to swap out implementations without changing the
// code that uses these abstractions.  For the PoC,
// let's just stick with a templated type.
// It can be refactored later to be an erased type
// pretty easily afterwards.
//
// As simple alternative solution would be to just alias
// the library types for each of this integration points.
// For example:
// using encoder_library = ::scale::encoder;
// Then:
// auto enc = encoder<encoder_library>{};
// make_key(enc, value);
// This would be a build time setting, which I actually like
// now that I think about it.  Hot swapping is not a design goal.
template <typename Library>
struct encoder {
  template <typename T>
  charter::schema::bytes_t encode(const T& obj);

  template <typename T>
  void encode(const T& obj, charter::schema::bytes_t& out);

  template <typename T>
  T decode(const charter::schema::bytes_view_t& bytes);

  template <typename T>
  std::optional<T> try_decode(const charter::schema::bytes_view_t& bytes);
};

}  // namespace charter::schema::encoding
