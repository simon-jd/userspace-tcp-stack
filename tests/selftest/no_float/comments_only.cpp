// Fixture for core.no_float_selftest_ok (not compiled): the words double and
// float only in comments and strings, and integer literals that look close.
/* A block comment: double float 1.5 */
const char* name = "double 1.5 float";
const char quote = '"';
const char dot = '.';
unsigned million = 1'000'000;
unsigned hex = 0x1e5;
int add(int a1, int b) { return a1 + b; }  // returns 2.0? no: an int
unsigned h = 0x12'5e7;
