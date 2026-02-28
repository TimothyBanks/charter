#pragma once

#include <charter/schema/apply_snapshot_chunk_result.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(
    charter::schema,
    apply_snapshot_chunk_result,
    charter::schema::apply_snapshot_chunk_result::unknown,
    charter::schema::apply_snapshot_chunk_result::accept,
    charter::schema::apply_snapshot_chunk_result::abort,
    charter::schema::apply_snapshot_chunk_result::retry,
    charter::schema::apply_snapshot_chunk_result::retry_snapshot,
    charter::schema::apply_snapshot_chunk_result::reject_snapshot)
