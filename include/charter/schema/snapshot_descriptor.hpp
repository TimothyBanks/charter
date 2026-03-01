#pragma once

#include <charter/schema/primitives.hpp>
#include <cstdint>

// Schema type: snapshot descriptor.
// Custody workflow: State sync metadata: describes snapshot
// height/format/hash/chunks for node bootstrap and recovery.
namespace charter::schema {

template <uint16_t Version>
struct snapshot_descriptor;

template <>
struct snapshot_descriptor<1> final {
  uint16_t version{1};
  uint64_t height{};
  uint32_t format{1};
  uint32_t chunks{1};
  hash32_t hash;
  bytes_t metadata;
};

using snapshot_descriptor_t = snapshot_descriptor<1>;

}  // namespace charter::schema
