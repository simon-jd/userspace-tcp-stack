// Types used by the entries of config_tx.def, owned like it by m1-tx: enums of
// new knobs and aliases for types with a top-level comma. The .def files are
// expanded several times, inside the TcpConfig and StackConfig bodies and
// inside functions, so they cannot declare types. Only m1-tx adds declarations
// here; config.hpp includes this file before TcpConfig. Integer types only
// (core.no_float).
#pragma once

#include <cstdint>
#include <optional>

#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {}  // namespace utcp
