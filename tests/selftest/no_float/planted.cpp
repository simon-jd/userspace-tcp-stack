// Fixture for core.no_float_selftest_bad (not compiled): a planted floating
// point type that ci/check-no-float.sh must report.
int scaled(int x) {
  double factor = 3;
  return static_cast<int>(x * factor);
}
