// Self-test input for ci/check-no-float.sh: an integer-only simulator header
// next to an exempt file. The words float and double in comments are fine.
#pragma once
inline long delay_plus_jitter(long delay_ns, long jitter_ns) { return delay_ns + jitter_ns; }
