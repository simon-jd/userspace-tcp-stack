// Storage geometry shared by StackConfig and the core's ChunkPool.
#pragma once

#include <cstdint>

namespace utcp {

#ifdef UTCP_RING_CHUNK_BYTES
inline constexpr std::uint32_t ring_chunk_bytes = UTCP_RING_CHUNK_BYTES;
#else
inline constexpr std::uint32_t ring_chunk_bytes = 4096;
#endif
static_assert(ring_chunk_bytes == 2048 || ring_chunk_bytes == 4096 || ring_chunk_bytes == 8192);
inline constexpr std::uint32_t default_chunk_limit = (1ULL << 32) / ring_chunk_bytes;

}  // namespace utcp
