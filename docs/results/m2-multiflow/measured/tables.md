# Multi-flow study

Brackets show the observed minimum and maximum across five matched repetitions. The reported convergence time is conditional on observing a full five-second hold. Where early sampling leaves the onset ambiguous, the first confirmed onset is an upper bound. Individual onset bounds and censoring horizons are in `runs.csv`. The common active cutoff uses each observed sender connect timestamp plus its registered write duration. The callback and last application write have no independent timestamps.

## Scenario 1

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.882 [0.790, 0.947] | 0.882 [0.790, 0.947] | 1/5 | 4 | 0 | 34.3 [34.3, 34.3] | 5 |
| baseline | 0.884 [0.866, 0.976] | 0.884 [0.866, 0.976] | 1/5 | 4 | 0 | 26.2 [26.2, 26.2] | 5 |

Test minus baseline median Jain was -0.001 in the nominal window and -0.002 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | stack cubic | Linux cubic | 79.271 [74.428, 80.253] | 76.598 [73.913, 79.424] | no gap |
| f1 · port 5202 | stack cubic | Linux cubic | 24.583 [23.000, 32.174] | 27.587 [24.356, 32.976] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-01.png) are `p019-a01-test` (rep 2), `p007-a01-baseline` (rep 1).

## Scenario 2

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.981 [0.975, 0.994] | 0.981 [0.975, 0.994] | 0/5 | 5 | 0 | — | 5 |
| baseline | 0.977 [0.954, 0.986] | 0.978 [0.954, 0.986] | 2/5 | 3 | 0 | 23.2 [15.9, 30.6] | 5 |

Test minus baseline median Jain was 0.004 in the nominal window and 0.003 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | stack cubic | Linux cubic | 30.117 [19.034, 36.341] | 33.937 [29.528, 34.931] | no gap |
| f1 · port 5202 | stack cubic | Linux cubic | 25.309 [21.515, 31.515] | 23.273 [17.769, 26.195] | no gap |
| f2 · port 5203 | stack cubic | Linux cubic | 23.602 [22.260, 28.658] | 26.217 [23.219, 27.212] | no gap |
| f3 · port 5204 | stack cubic | Linux cubic | 21.323 [18.990, 24.464] | 19.597 [14.948, 25.797] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-02.png) are `p026-a01-test` (rep 3), `p025-a01-baseline` (rep 5).

## Scenario 3

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.983 [0.965, 0.985] | 0.983 [0.965, 0.985] | 0/5 | 5 | 0 | — | 5 |
| baseline | 0.963 [0.938, 0.980] | 0.963 [0.938, 0.980] | 0/5 | 5 | 0 | — | 5 |

Test minus baseline median Jain was 0.020 in the nominal window and 0.020 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | stack cubic | Linux cubic | 12.293 [7.807, 14.779] | 11.476 [10.738, 15.897] | no gap |
| f1 · port 5202 | stack cubic | Linux cubic | 11.298 [9.004, 16.899] | 13.381 [11.568, 15.314] | no gap |
| f2 · port 5203 | stack cubic | Linux cubic | 11.716 [11.000, 13.104] | 12.232 [9.524, 14.404] | no gap |
| f3 · port 5204 | stack cubic | Linux cubic | 11.040 [10.682, 13.402] | 12.049 [9.145, 13.028] | no gap |
| f4 · port 5205 | stack cubic | Linux cubic | 11.913 [11.354, 16.229] | 11.676 [11.023, 15.691] | no gap |
| f5 · port 5206 | stack cubic | Linux cubic | 14.231 [11.759, 17.679] | 11.612 [11.287, 16.923] | no gap |
| f6 · port 5207 | stack cubic | Linux cubic | 11.981 [11.100, 13.290] | 13.018 [10.009, 14.456] | no gap |
| f7 · port 5208 | stack cubic | Linux cubic | 12.094 [10.579, 14.246] | 11.871 [10.712, 13.807] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-03.png) are `p029-a01-test` (rep 3), `p044-a01-baseline` (rep 2).

## Scenario 4

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.995 [0.993, 1.000] | 0.995 [0.993, 1.000] | 5/5 | 0 | 0 | 6.2 [1.1, 20.7] | 5 |
| baseline | 1.000 [0.996, 1.000] | 1.000 [0.996, 1.000] | 5/5 | 0 | 0 | 11.5 [11.3, 21.0] | 5 |

Test minus baseline median Jain was -0.004 in the nominal window and -0.004 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | stack newreno | Linux newreno | 63.647 [60.457, 68.050] | 65.660 [65.382, 68.078] | no gap |
| f1 · port 5202 | stack newreno | Linux newreno | 46.826 [39.944, 48.320] | 43.752 [39.988, 43.976] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-04.png) are `p046-a01-test` (rep 3), `p037-a01-baseline` (rep 2).

## Scenario 5

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.993 [0.978, 1.000] | 0.993 [0.978, 1.000] | 5/5 | 0 | 0 | 8.7 [2.3, 14.5] | 5 |
| baseline | 0.981 [0.970, 1.000] | 0.981 [0.970, 1.000] | 5/5 | 0 | 0 | 2.4 [2.3, 13.3] | 5 |

Test minus baseline median Jain was 0.012 in the nominal window and 0.012 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | stack bbr | Linux bbr | 59.664 [56.885, 60.690] | 59.975 [56.887, 61.710] | no gap |
| f1 · port 5202 | stack bbr | Linux bbr | 48.511 [44.704, 50.739] | 46.570 [44.068, 50.435] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-05.png) are `p040-a01-test` (rep 5), `p014-a01-baseline` (rep 3).

## Scenario 6

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.830 [0.714, 0.881] | 0.830 [0.714, 0.880] | 0/5 | 5 | 0 | — | 5 |
| baseline | 0.790 [0.762, 0.881] | 0.790 [0.762, 0.881] | 0/5 | 5 | 0 | — | 5 |

Test minus baseline median Jain was 0.040 in the nominal window and 0.040 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | linux cubic | Linux cubic | 77.941 [77.394, 85.070] | 80.619 [76.570, 82.603] | no gap |
| f1 · port 5202 | stack newreno | Linux newreno | 26.294 [15.188, 27.203] | 22.084 [19.069, 28.234] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-06.png) are `p028-a01-test` (rep 4), `p049-a01-baseline` (rep 5).

## Scenario 7

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.858 [0.821, 0.872] | 0.858 [0.821, 0.871] | 0/5 | 5 | 0 | — | 5 |
| baseline | 0.873 [0.833, 0.975] | 0.873 [0.833, 0.975] | 1/5 | 4 | 0 | 28.9 [28.9, 28.9] | 5 |

Test minus baseline median Jain was -0.014 in the nominal window and -0.014 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | linux cubic | Linux cubic | 79.561 [78.567, 81.403] | 79.274 [74.616, 79.864] | no gap |
| f1 · port 5202 | stack cubic | Linux cubic | 24.094 [21.190, 25.662] | 24.531 [23.597, 31.866] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-07.png) are `p024-a01-test` (rep 2), `p030-a01-baseline` (rep 1).

## Scenario 8

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.878 [0.848, 0.993] | 0.877 [0.848, 0.993] | 0/5 | 5 | 0 | — | 5 |
| baseline | 0.996 [0.901, 1.000] | 0.996 [0.900, 1.000] | 0/5 | 5 | 0 | — | 5 |

Test minus baseline median Jain was -0.119 in the nominal window and -0.119 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | linux cubic | Linux cubic | 44.093 [43.551, 54.093] | 51.449 [45.525, 51.990] | no gap |
| f1 · port 5202 | stack bbr | Linux bbr | 69.932 [56.127, 70.589] | 59.568 [57.331, 68.337] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-08.png) are `p003-a01-test` (rep 1), `p022-a01-baseline` (rep 3).

## Scenario 9

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.992 [0.984, 1.000] | 0.992 [0.984, 1.000] | 5/5 | 0 | 0 | 38.5 [22.3, 74.9] | 5 |
| baseline | 0.995 [0.975, 0.998] | 0.995 [0.975, 0.998] | 5/5 | 0 | 0 | 43.1 [32.1, 58.8] | 5 |

Test minus baseline median Jain was -0.003 in the nominal window and -0.003 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | stack cubic | Linux cubic | 6.213 [5.756, 6.394] | 6.173 [6.082, 6.461] | no gap |
| f1 · port 5202 | stack cubic | Linux cubic | 4.014 [3.768, 4.475] | 4.059 [3.709, 4.169] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-09.png) are `p018-a01-test` (rep 4), `p045-a01-baseline` (rep 3).

## Scenario 10

| Side | Nominal Jain | Fully active Jain | Converged / 5 | Right-censored | Sampling unobserved | First confirmed onset, s | Flagged runs |
|---|---|---|---:|---:|---:|---|---:|
| test | 0.935 [0.895, 0.977] | 0.935 [0.895, 0.977] | 0/5 | 5 | 0 | — | 5 |
| baseline | 0.972 [0.956, 0.998] | 0.972 [0.956, 0.998] | 1/5 | 4 | 0 | 29.7 [29.7, 29.7] | 5 |

Test minus baseline median Jain was -0.037 in the nominal window and -0.037 in the fully active window.

| Physical flow | Test sender | Baseline sender | Own-window test Mbit/s | Own-window baseline Mbit/s | Gap |
|---|---|---|---|---|---|
| f0 · port 5201 | stack cubic | Linux cubic | 18.141 [17.678, 21.730] | 33.087 [28.066, 35.186] | gap |
| f1 · port 5202 | linux cubic | Linux cubic | 35.034 [30.606, 36.407] | 24.517 [21.919, 28.265] | gap |
| f2 · port 5203 | linux cubic | Linux cubic | 30.742 [23.955, 34.651] | 24.143 [20.192, 27.265] | no gap |
| f3 · port 5204 | stack cubic | Linux cubic | 19.376 [12.728, 23.524] | 21.883 [16.443, 26.495] | no gap |

The two real runs selected for the [per-flow plot](plots/scenario-10.png) are `p047-a01-test` (rep 1), `p035-a01-baseline` (rep 3).

## Eight-flow loop lateness

Each row compares the five serial one-flow CUBIC controls of 30 seconds with a single physical sender role across five 60-second eight-flow CUBIC scenarios. The seven incumbents have 60-second registered writes and the late f7 sender has a 40-second registered write. Both use the same slot and runtime key. Each p99 or maximum describes one process's whole-process timer lateness. The p99 is the inclusive upper bound of its logarithmic histogram bucket, capped at the exact maximum. Maxima depend on observation length and timer count. Exposure, histogram counts and sender sample spans appear in `eight-vs-one-lateness.csv`, `flows.csv` and `one-flow-controls.csv`.

| Physical flow | Histogram metric | One flow, µs | Eight flows, µs | Median timer observations, one / eight |
|---|---|---|---|---|
| f0 | p99 | 262.143 [131.071, 262.143] | 65.535 [65.535, 131.071] | 4609 / 6703 |
| f0 | max | 2122.062 [1881.791, 44159.444] | 1950.204 [1524.140, 46807.901] | 4609 / 6703 |
| f1 | p99 | 262.143 [131.071, 262.143] | 65.535 [65.535, 262.143] | 4609 / 6643 |
| f1 | max | 2122.062 [1881.791, 44159.444] | 2852.633 [2054.993, 62924.776] | 4609 / 6643 |
| f2 | p99 | 262.143 [131.071, 262.143] | 65.535 [65.535, 65.535] | 4609 / 6622 |
| f2 | max | 2122.062 [1881.791, 44159.444] | 2482.524 [1837.658, 44781.292] | 4609 / 6622 |
| f3 | p99 | 262.143 [131.071, 262.143] | 131.071 [65.535, 131.071] | 4609 / 6575 |
| f3 | max | 2122.062 [1881.791, 44159.444] | 2927.292 [2009.923, 37226.626] | 4609 / 6575 |
| f4 | p99 | 262.143 [131.071, 262.143] | 65.535 [65.535, 65.535] | 4609 / 6688 |
| f4 | max | 2122.062 [1881.791, 44159.444] | 2021.191 [1541.236, 41380.159] | 4609 / 6688 |
| f5 | p99 | 262.143 [131.071, 262.143] | 65.535 [65.535, 262.143] | 4609 / 6754 |
| f5 | max | 2122.062 [1881.791, 44159.444] | 2489.036 [1803.030, 67044.004] | 4609 / 6754 |
| f6 | p99 | 262.143 [131.071, 262.143] | 65.535 [65.535, 65.535] | 4609 / 6608 |
| f6 | max | 2122.062 [1881.791, 44159.444] | 2259.320 [1356.067, 66930.095] | 4609 / 6608 |
| f7 | p99 | 262.143 [131.071, 262.143] | 65.535 [65.535, 262.143] | 4609 / 4418 |
| f7 | max | 2122.062 [1881.791, 44159.444] | 2101.352 [1697.042, 54644.249] | 4609 / 4418 |

