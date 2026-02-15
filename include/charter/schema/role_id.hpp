#pragma once

namespace charter::schema {

enum class role_id_t : uint8_t {
  initiator = 0,
  approver = 1,
  executor = 2,
  admin = 3,
  auditor = 4,
  guardian = 5,
  attestor = 6
};

}