#pragma once

#include <charter/schema/offer_snapshot_result.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(
    charter::schema,
    offer_snapshot_result,
    charter::schema::offer_snapshot_result::unknown,
    charter::schema::offer_snapshot_result::accept,
    charter::schema::offer_snapshot_result::abort,
    charter::schema::offer_snapshot_result::reject,
    charter::schema::offer_snapshot_result::reject_format,
    charter::schema::offer_snapshot_result::reject_sender)
