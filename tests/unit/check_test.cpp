#include "utcp/check.hpp"

#include <gtest/gtest.h>

namespace {

int evaluations = 0;

bool counted(bool v) {
  ++evaluations;
  return v;
}

TEST(CheckDeathTest, CheckAbortsWithTheExpression) {
  EXPECT_DEATH(UTCP_CHECK(1 + 1 == 3), "UTCP_CHECK\\(1 \\+ 1 == 3\\)");
}

TEST(Check, PassingCheckEvaluatesOnce) {
  evaluations = 0;
  UTCP_CHECK(counted(true));
  EXPECT_EQ(evaluations, 1);
}

TEST(Check, DcheckFollowsTheBuildType) {
  evaluations = 0;
  UTCP_DCHECK(counted(true));
  EXPECT_EQ(evaluations, UTCP_DCHECK_IS_ON ? 1 : 0);
}

#if UTCP_DCHECK_IS_ON
TEST(CheckDeathTest, DcheckAbortsWhenOn) { EXPECT_DEATH(UTCP_DCHECK(counted(false)), "UTCP_DCHECK"); }
#else
TEST(Check, DcheckIsNotEvaluatedWhenOff) {
  evaluations = 0;
  UTCP_DCHECK(counted(false));
  EXPECT_EQ(evaluations, 0);
}
#endif

}  // namespace
