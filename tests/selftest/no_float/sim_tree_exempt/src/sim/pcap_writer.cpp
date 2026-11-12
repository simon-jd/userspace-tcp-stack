// Self-test input for ci/check-no-float.sh: an opted-out simulator file.
// utcp-no-float: exempt (output only: prints the wall time in seconds)
double wall_seconds(long ns) { return static_cast<double>(ns) / 1e9; }
