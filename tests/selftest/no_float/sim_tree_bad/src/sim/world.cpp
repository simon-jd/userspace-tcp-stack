// Self-test input for ci/check-no-float.sh: a simulator file whose name is
// not scenario*, gen* or link* must still be checked.
int jitter_ns(int delay_ns) { return static_cast<int>(delay_ns * 0.25); }
