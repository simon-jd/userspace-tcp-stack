// Types used by the entries of config_tcp.def, owned like it by the TCP engine
// (m1-tcp-core, then m1-tcp-robust): enums of new knobs and aliases for types
// with a top-level comma. The .def files are expanded several times, inside the
// TcpConfig and StackConfig bodies and inside functions, so they cannot declare
// types. Only those tasks add declarations here; config.hpp includes this file
// before TcpConfig. Integer types only (core.no_float).
#pragma once

#include <cstdint>
#include <optional>

#include "utcp/time.hpp"
#include "utcp/types.hpp"

namespace utcp {}  // namespace utcp
