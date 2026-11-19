### A1 · 100 Mbit/s, 20 ms

Medians and observed ranges across the first five valid pairs. Retransmission is a percentage of transmitted data segments. Queueing delays are in milliseconds.

| Sender | Goodput (Mbit/s) | Retransmission (%) | Queue p50 (ms) | Queue p99 (ms) |
|---|---:|---:|---:|---:|
| RFC | 8.338 [8.106, 8.636] | 0.999 [0.920, 1.046] | -0.01254 [-0.04610, -0.00161] | 0.09134 [0.06352, 0.15928] |
| RFC + RTO/estimator | 8.068 [7.807, 9.223] | 1.055 [0.867, 1.097] | -0.01684 [-0.03895, -0.01258] | 0.10658 [0.06253, 0.15236] |
| RFC + PRR | 8.213 [7.393, 8.998] | 0.965 [0.894, 1.148] | -0.01094 [-0.01507, -0.00171] | 0.10520 [0.05489, 0.14844] |
| RFC + IW10 | 8.233 [7.752, 9.278] | 0.946 [0.917, 1.043] | -0.01019 [-0.02337, -0.00245] | 0.08174 [0.07014, 0.12815] |
| RFC + classic HyStart | 8.018 [7.665, 8.220] | 1.045 [1.011, 1.099] | -0.00988 [-0.03009, -0.00525] | 0.09374 [0.04025, 0.09968] |
| RFC + all four | 8.341 [8.163, 8.575] | 1.000 [0.943, 1.019] | -0.00758 [-0.03900, 0.02007] | 0.05546 [0.02614, 0.13516] |
| Linux-compatible stack | 5.975 [5.707, 6.385] | 1.048 [0.965, 1.112] | -0.00907 [-0.02134, -0.00136] | 0.05378 [0.04468, 0.07638] |
| Linux CUBIC | 6.138 [5.976, 6.288] | 1.006 [0.973, 1.094] | -0.00846 [-0.01784, 0.00992] | 0.06870 [0.06122, 0.08285] |

| Stack sender | Linux control | Goodput | Retransmission | Queue p50 | Queue p99 |
|---|---|---|---|---|---|
| RFC | Common | gap | no gap | no gap | no gap |
| Linux-compatible stack | Common | no gap | no gap | no gap | no gap |
| RFC | RFC-paired | gap | no gap | no gap | no gap |

| Change | Share of signed RFC-to-Linux goodput gap (%) |
|---|---:|
| RFC + RTO/estimator | 12.31 [-61.46, 35.31] |
| RFC + PRR | 5.70 [-49.06, 52.93] |
| RFC + IW10 | 4.81 [-64.49, 37.63] |
| RFC + classic HyStart | 14.57 [-6.28, 41.37] |
| RFC + all four | -0.14 [-25.81, 20.14] |
| interaction | -37.52 [-164.65, 178.14] |

The unattributed goodput difference (Linux-compatible minus all-four) was -2.366 [-2.868, -1.778] Mbit/s.

- Lower goodput than the common Linux median occurred with Linux-compatible stack.
- Higher retransmission than the common Linux median occurred with RFC + RTO/estimator, RFC + classic HyStart, Linux-compatible stack.
- Higher p50 delay than the common Linux median occurred with RFC + all four.
- Higher p99 delay than the common Linux median occurred with RFC, RFC + RTO/estimator, RFC + PRR, RFC + IW10, RFC + classic HyStart.

Counts across all physical transfers were 69 with `foreign_cpu`, 6 with `rwnd_limited_frac`, 1 with `time_squeeze`.

### A2 · 10 Mbit/s, 100 ms

Medians and observed ranges across the first five valid pairs. Retransmission is a percentage of transmitted data segments. Queueing delays are in milliseconds.

| Sender | Goodput (Mbit/s) | Retransmission (%) | Queue p50 (ms) | Queue p99 (ms) |
|---|---:|---:|---:|---:|
| RFC | 1.646 [1.484, 1.849] | 0.951 [0.804, 1.250] | -0.00418 [-0.01048, -0.00099] | 0.85756 [0.72096, 1.10865] |
| RFC + RTO/estimator | 1.684 [1.545, 1.687] | 0.981 [0.869, 1.082] | -0.01765 [-0.02206, -0.00948] | 0.59875 [0.43930, 1.04653] |
| RFC + PRR | 1.641 [1.556, 1.672] | 1.029 [0.939, 1.114] | -0.00882 [-0.01900, -0.00344] | 1.04881 [0.85873, 1.12886] |
| RFC + IW10 | 1.639 [1.558, 1.750] | 0.961 [0.861, 1.086] | -0.01699 [-0.04346, -0.01136] | 0.97469 [0.88352, 1.06849] |
| RFC + classic HyStart | 1.669 [1.546, 1.726] | 1.017 [0.910, 1.137] | -0.00696 [-0.01385, 0.01919] | 1.04436 [0.96595, 1.14722] |
| RFC + all four | 1.625 [1.591, 1.767] | 1.049 [0.815, 1.092] | -0.00699 [-0.01455, 0.00215] | 0.68208 [0.55695, 1.09233] |
| Linux-compatible stack | 1.300 [1.182, 1.434] | 1.011 [0.874, 1.139] | -0.00677 [-0.01003, -0.00411] | 0.82682 [0.19641, 0.97237] |
| Linux CUBIC | 1.335 [1.182, 1.473] | 0.931 [0.881, 1.148] | -0.00636 [-0.00836, -0.00484] | 0.81943 [0.66210, 0.98151] |

| Stack sender | Linux control | Goodput | Retransmission | Queue p50 | Queue p99 |
|---|---|---|---|---|---|
| RFC | Common | gap | no gap | no gap | no gap |
| Linux-compatible stack | Common | no gap | no gap | no gap | no gap |
| RFC | RFC-paired | no gap | no gap | no gap | no gap |

| Change | Share of signed RFC-to-Linux goodput gap (%) |
|---|---:|
| RFC + RTO/estimator | -12.15 [-1810.37, 80.75] |
| RFC + PRR | 1.43 [-1678.02, 77.94] |
| RFC + IW10 | 2.10 [-2376.23, 77.33] |
| RFC + classic HyStart | -7.60 [-2159.12, 80.41] |
| RFC + all four | 6.79 [-2530.59, 68.57] |
| interaction | 23.01 [-294.72, 7067.69] |

The unattributed goodput difference (Linux-compatible minus all-four) was -0.325 [-0.585, -0.157] Mbit/s.

- Lower goodput than the common Linux median occurred with Linux-compatible stack.
- Higher retransmission than the common Linux median occurred with RFC, RFC + RTO/estimator, RFC + PRR, RFC + IW10, RFC + classic HyStart, RFC + all four, Linux-compatible stack.
- Higher p50 delay than the common Linux median occurred with RFC.
- Higher p99 delay than the common Linux median occurred with RFC, RFC + PRR, RFC + IW10, RFC + classic HyStart, Linux-compatible stack.

Counts across all physical transfers were 2 with `capture_mismatch:total_retrans`, 68 with `foreign_cpu`, 2 with `time_squeeze`.
