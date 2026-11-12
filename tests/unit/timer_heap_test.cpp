#include "core/timer/timer_heap.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <vector>

namespace {

using utcp::Time;
using utcp::TimerHeap;
using utcp::TimerId;
using utcp::TimerKey;
using utcp::TimerKind;

std::vector<TimerId> fire_all(TimerHeap& h, Time now) {
  std::vector<TimerId> out;
  while (const auto f = h.pop_due(now)) {
    out.push_back(f->id);
  }
  return out;
}

TEST(TimerHeap, EqualDeadlinesFireInArmOrder) {
  TimerHeap h;
  std::vector<TimerId> ids;
  for (std::uint32_t i = 0; i < 10; ++i) {
    ids.push_back(h.create(i, TimerKind::delack));
  }
  // Arm in a scrambled order, all at the same deadline.
  const std::vector<int> order{3, 7, 0, 9, 1, 8, 2, 6, 4, 5};
  for (const int i : order) {
    h.arm(ids[static_cast<std::size_t>(i)], Time{1000});
  }
  h.fix_up();
  EXPECT_EQ(h.next_deadline(), Time{1000});
  EXPECT_TRUE(fire_all(h, Time{999}).empty());
  const auto fired = fire_all(h, Time{1000});
  ASSERT_EQ(fired.size(), order.size());
  for (std::size_t i = 0; i < order.size(); ++i) {
    EXPECT_EQ(fired[i], ids[static_cast<std::size_t>(order[i])]);
  }
  EXPECT_EQ(h.next_deadline(), Time::never());
  h.check_invariants();
}

TEST(TimerHeap, FiredTimerCarriesOwnerKindAndKey) {
  TimerHeap h;
  const TimerId a = h.create(42, TimerKind::time_wait);
  h.arm(a, Time{5});
  const auto f = h.pop_due(Time{100});
  ASSERT_TRUE(f.has_value());
  EXPECT_EQ(f->id, a);
  EXPECT_EQ(f->owner, 42u);
  EXPECT_EQ(f->kind, TimerKind::time_wait);
  EXPECT_EQ(f->key.deadline, Time{5});
  EXPECT_FALSE(h.armed(a));
  EXPECT_EQ(h.deadline(a), Time::never());
  // Still allocated: it can be armed again.
  h.arm(a, Time{200});
  EXPECT_TRUE(h.armed(a));
}

TEST(TimerHeap, Cancel) {
  TimerHeap h;
  const TimerId a = h.create(1, TimerKind::xmit);
  const TimerId b = h.create(2, TimerKind::xmit);
  const TimerId c = h.create(3, TimerKind::xmit);
  h.arm(a, Time{10});
  h.arm(b, Time{20});
  h.arm(c, Time{30});
  h.cancel(b);
  h.cancel(b);  // no-op when unarmed
  EXPECT_FALSE(h.armed(b));
  EXPECT_EQ(h.armed_count(), 2u);
  h.check_invariants();
  EXPECT_EQ(fire_all(h, Time{100}), (std::vector<TimerId>{a, c}));
}

TEST(TimerHeap, RearmEarlierAndLater) {
  TimerHeap h;
  const TimerId a = h.create(1, TimerKind::xmit);
  const TimerId b = h.create(2, TimerKind::delack);
  h.arm(a, Time{100});
  h.arm(b, Time{50});
  h.arm(a, Time{10});  // earlier: moves up at once
  h.fix_up();
  EXPECT_EQ(h.next_deadline(), Time{10});
  EXPECT_EQ(h.deadline(a), Time{10});
  h.arm(a, Time{70});  // later: lazy
  EXPECT_EQ(h.deadline(a), Time{70});
  h.fix_up();
  EXPECT_EQ(h.next_deadline(), Time{50});
  h.check_invariants();
  EXPECT_EQ(fire_all(h, Time{60}), (std::vector<TimerId>{b}));
  EXPECT_EQ(fire_all(h, Time{70}), (std::vector<TimerId>{a}));
}

TEST(TimerHeap, LazyRearmUsesTheLastArmSequence) {
  TimerHeap h;
  const TimerId a = h.create(1, TimerKind::xmit);
  const TimerId b = h.create(2, TimerKind::xmit);
  h.arm(a, Time{10});  // arm_seq 0
  h.arm(b, Time{20});  // arm_seq 1
  h.arm(a, Time{20});  // later, lazy: effective key (20, arm_seq 2)
  // a was the top, so the heap repaired it at once.
  EXPECT_EQ(h.next_deadline(), Time{20});
  h.check_invariants();
  // Effective keys (20, 1) < (20, 2): b fires before a.
  const auto first = h.pop_due(Time{20});
  ASSERT_TRUE(first.has_value());
  EXPECT_EQ(first->id, b);
  EXPECT_EQ(first->key, (TimerKey{Time{20}, 1}));
  const auto second = h.pop_due(Time{20});
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(second->id, a);
  EXPECT_EQ(second->key, (TimerKey{Time{20}, 2}));
}

TEST(TimerHeap, PopDueRepairsStaleTopsWithoutFixUp) {
  TimerHeap h;
  const TimerId a = h.create(1, TimerKind::xmit);
  h.arm(a, Time{10});
  h.arm(a, Time{1000});  // lazy
  EXPECT_FALSE(h.pop_due(Time{500}).has_value());
  EXPECT_EQ(h.next_deadline(), Time{1000});  // pop_due left the top exact
  EXPECT_TRUE(h.pop_due(Time{1000}).has_value());
}

// Removing the top can expose an entry whose heap key is stale (lazily
// re-armed while below the top). The heap repairs it in the same call, so
// next_deadline() is exact without a separate fix_up().
TEST(TimerHeap, RemovingTheTopRepairsAStaleEntryBelowIt) {
  for (int how = 0; how < 3; ++how) {
    TimerHeap h;
    const TimerId a = h.create(1, TimerKind::xmit);
    const TimerId b = h.create(2, TimerKind::xmit);
    const TimerId c = h.create(3, TimerKind::xmit);
    h.arm(a, Time{10});
    h.arm(b, Time{20});
    h.arm(c, Time{25});
    h.arm(b, Time{30});  // lazy: b keeps heap key 20 below a
    EXPECT_EQ(h.next_deadline(), Time{10});
    if (how == 0) {
      h.cancel(a);
    } else if (how == 1) {
      h.destroy(a);
    } else {
      const auto f = h.pop_due(Time{10});
      ASSERT_TRUE(f.has_value());
      EXPECT_EQ(f->id, a);
    }
    // Earliest armed deadline is c's 25, not b's stale 20 or wanted 30.
    EXPECT_EQ(h.next_deadline(), Time{25}) << how;
    h.check_invariants();
    EXPECT_EQ(fire_all(h, Time{100}), (std::vector<TimerId>{c, b})) << how;
  }
}

TEST(TimerHeap, LazyRearmOfTheTopIsExactAtOnce) {
  TimerHeap h;
  const TimerId a = h.create(1, TimerKind::xmit);
  const TimerId b = h.create(2, TimerKind::delack);
  h.arm(a, Time{10});
  h.arm(b, Time{40});
  h.arm(a, Time{50});  // the top moves later
  EXPECT_EQ(h.next_deadline(), Time{40});
  h.check_invariants();
}

TEST(TimerHeapDeathTest, NoTimerIsNeverHandedOut) {
  TimerHeap h;
  EXPECT_NE(h.create(0, TimerKind::xmit), utcp::no_timer);
  EXPECT_DEATH(h.destroy(utcp::no_timer), "UTCP_CHECK");
  EXPECT_DEATH(h.cancel(utcp::no_timer), "UTCP_CHECK");
}

TEST(TimerHeap, IdsAreReusedLowestFirst) {
  TimerHeap h;
  const TimerId a = h.create(0, TimerKind::xmit);
  const TimerId b = h.create(0, TimerKind::xmit);
  const TimerId c = h.create(0, TimerKind::xmit);
  EXPECT_EQ(a, 0u);
  EXPECT_EQ(b, 1u);
  EXPECT_EQ(c, 2u);
  h.arm(b, Time{1});
  h.destroy(c);
  h.destroy(b);  // also cancels
  EXPECT_EQ(h.armed_count(), 0u);
  EXPECT_EQ(h.timer_count(), 1u);
  EXPECT_EQ(h.create(7, TimerKind::pace), 1u);
  EXPECT_EQ(h.create(8, TimerKind::pace), 2u);
  EXPECT_EQ(h.create(9, TimerKind::pace), 3u);
  EXPECT_EQ(h.owner(1), 7u);
  EXPECT_EQ(h.kind(1), TimerKind::pace);
  h.check_invariants();
}

TEST(TimerHeap, NeverDeadline) {
  TimerHeap h;
  const TimerId a = h.create(0, TimerKind::keepalive);
  h.arm(a, Time::never());
  h.fix_up();
  EXPECT_EQ(h.next_deadline(), Time::never());
  EXPECT_FALSE(h.pop_due(Time{std::numeric_limits<std::int64_t>::max() - 1}).has_value());
}

// Reference: a vector of armed (effective key, id) entries, kept sorted.
class Reference {
public:
  void arm(TimerId id, Time deadline) {
    cancel(id);
    const TimerKey k{deadline, seq_++};
    entries_.insert(std::upper_bound(entries_.begin(), entries_.end(), std::pair{k, id}),
                    std::pair{k, id});
  }
  void cancel(TimerId id) {
    std::erase_if(entries_, [id](const auto& e) { return e.second == id; });
  }
  [[nodiscard]] Time next() const {
    return entries_.empty() ? Time::never() : entries_.front().first.deadline;
  }
  std::optional<std::pair<TimerKey, TimerId>> pop(Time now) {
    if (entries_.empty() || entries_.front().first.deadline > now) {
      return std::nullopt;
    }
    const auto e = entries_.front();
    entries_.erase(entries_.begin());
    return e;
  }
  [[nodiscard]] std::size_t size() const { return entries_.size(); }
  [[nodiscard]] std::optional<Time> deadline(TimerId id) const {
    for (const auto& e : entries_) {
      if (e.second == id) {
        return e.first.deadline;
      }
    }
    return std::nullopt;
  }

private:
  std::vector<std::pair<TimerKey, TimerId>> entries_;
  std::uint64_t seq_ = 0;
};

TEST(TimerHeap, DifferentialAgainstSortedVector) {
  TimerHeap h;
  Reference ref;
  std::mt19937_64 gen(6298);
  std::vector<TimerId> live;
  std::map<TimerId, std::uint32_t> owners;
  std::int64_t now = 1'000'000;
  std::size_t fired = 0;
  std::size_t rearm_earlier = 0;
  std::size_t rearm_later = 0;  // lazy: same or later deadline

  for (int step = 0; step < 100'000; ++step) {
    const auto op = gen() % 100;
    // At most 64 live timers, so that most arms hit an armed timer.
    if (live.empty() || (op < 8 && live.size() < 64)) {
      const auto owner = static_cast<std::uint32_t>(gen());
      const TimerId id = h.create(owner, static_cast<TimerKind>(gen() % utcp::timer_kind_count));
      ASSERT_EQ(std::count(live.begin(), live.end(), id), 0);
      live.push_back(id);
      owners[id] = owner;
    } else if (op < 12 && live.size() > 1) {
      const std::size_t i = gen() % live.size();
      h.destroy(live[i]);
      ref.cancel(live[i]);
      live.erase(live.begin() + static_cast<long>(i));
    } else if (op < 60) {
      const TimerId id = live[gen() % live.size()];
      // Coarse deadlines so that many keys tie on the deadline.
      const std::int64_t d = now + static_cast<std::int64_t>(gen() % 64) * 1000;
      if (const auto cur = ref.deadline(id)) {
        (Time{d} < *cur ? rearm_earlier : rearm_later) += 1;
      }
      h.arm(id, Time{d});
      ref.arm(id, Time{d});
    } else if (op < 70) {
      const TimerId id = live[gen() % live.size()];
      h.cancel(id);
      ref.cancel(id);
    } else {
      now += static_cast<std::int64_t>(gen() % 3000);
      for (;;) {
        const auto want = ref.pop(Time{now});
        const auto got = h.pop_due(Time{now});
        ASSERT_EQ(want.has_value(), got.has_value()) << "step " << step;
        if (!want) {
          break;
        }
        ASSERT_EQ(got->id, want->second) << "step " << step;
        ASSERT_EQ(got->key, want->first) << "step " << step;
        ASSERT_EQ(got->owner, owners[got->id]);
        ++fired;
      }
    }
    // Exact after every call; fix_up() only on some steps.
    ASSERT_EQ(h.next_deadline(), ref.next()) << "step " << step;
    if (step % 7 == 0) {
      h.fix_up();
    }
    ASSERT_EQ(h.armed_count(), ref.size()) << "step " << step;
    if (step % 1000 == 0) {
      h.check_invariants();
    }
  }
  h.check_invariants();
  EXPECT_GT(fired, 10'000u);
  EXPECT_GT(rearm_earlier, 5'000u);
  EXPECT_GT(rearm_later, 5'000u);
}

}  // namespace
