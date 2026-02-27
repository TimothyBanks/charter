#pragma once

#include <charter/schema/security_event_type.hpp>
#include <scale/scale.hpp>

SCALE_DEFINE_ENUM_VALUE_LIST(
    charter::schema,
    security_event_type_t,
    charter::schema::security_event_type_t::tx_validation_failed,
    charter::schema::security_event_type_t::tx_execution_denied,
    charter::schema::security_event_type_t::authz_denied,
    charter::schema::security_event_type_t::policy_denied,
    charter::schema::security_event_type_t::replay_checkpoint_mismatch,
    charter::schema::security_event_type_t::snapshot_rejected,
    charter::schema::security_event_type_t::snapshot_applied,
    charter::schema::security_event_type_t::backup_import_failed,
    charter::schema::security_event_type_t::role_assignment_updated,
    charter::schema::security_event_type_t::signer_quarantine_updated,
    charter::schema::security_event_type_t::degraded_mode_updated)
