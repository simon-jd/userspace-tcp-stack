# M3 original stock Gen6 independent acceptance, 2026-11-23

Copied from the reviewer's worktree (`~/Desktop/utcp-wt/m3-stock-gen6-independent-evidence-n23/acceptance.md`) with two edits only: home-directory paths are written as `~`, and the word "private" before `main` is dropped. The [development receipt](stock-gen6-2026-11-23.md) has the campaign hashes.

## Scope and frozen inputs

This review is independent of the development worktree and does not promote or push `main`. The `main` observed during review was `1c83a38d784eef4c96d90edc6cb30beff1048425`. The pre-fix campaign source was `51275ccd3d2693f9a0e94d4e346acdcb05a49284` (tree `c5746e8cebc9a79d74c0356bbe7febbb8b2b9822`). The corrected code candidate is its direct child `fc4682954139542d3b8431753117d4e5431cbc1c` (tree `863f686ca1f4cae3283aec4736435cbd9e547fcf`). The exact diff changes only `src/core/tcp/recovery.cpp` and adds a regression in `tests/unit/recovery_test.cpp`. It changes no generator, runner, simulator checker, profile, or campaign thresholds. The pre-fix regression log records the expected failure (`N10` and flight 10 versus expected retransmission `P9` and flight 9); the independent corrected build passes all three `RecoveryTlpProbe` tests.

The proposed promotion commit is `1cbc15e232b5a413f49fea07584251502b9b1206` (tree `f8dc31b3af8d2b44667fd2e91fb68fd196c9640b`), whose direct parent is `fc468295`. Its sole delta is the added development receipt `docs/results/m3-sim/stock-gen6-2026-11-23.md` (SHA-256 `d607412962fa71b691de501fd97ae23381553c5c7770b9a83bed56369d5428a3`). Therefore its production, test, runner, and profile files are byte-identical to the audited corrected code commit. I checked its campaign hashes, 1,090-test CTest record, seven fixed TShark shard exits and 8,000 total decoded captures, 8,008 original decoded captures, scenario-field diversity counts, original failure scenario defaults, and raw artifact paths. The receipt has no Markdown links to resolve and no conflicting factual claim was found.

Acceptance was registered before the fixed result: 3A requires one million unique stock Gen6 seeds `[0,1000000)`, zero checker/process failures, valid receipts, and independent build/checks. 3B requires every registered serialized replay to match and contain a trace plus four captures. The registered list is exactly seeds divisible by 500 (2,000), and the original campaign also requires replays of its two nonregistered failure seeds. The corrected campaign has no failure seeds, so it requires 2,000 registered replays; the original two failing scenarios are independently rerun against the corrected binary.

Both plans use `gen6-stock-v1`, `--gen-version 6 --nodes stack --strict-fast-rexmit` for generation, `--strict-fast-rexmit` for serialized replay, shard size 1,000, timeout 120 seconds, and `nice 10`. The unchanged runner SHA-256 is `ffd1e5f2011e520cfd0697b24df078ed0cf2d4739f1f99e349ab65c362417b6e`; the registered seed list SHA-256 is `a4582364d3ed9cb03708145d27535120c1a5bc4fe46b3761f1e4cdfef5334d8c` in both campaigns.

## Campaign evidence

| Campaign | Source | Plan SHA-256 | Summary SHA-256 | Primary | Replays | Delivery |
|---|---|---|---|---|---|---|
| Original frozen `~/Desktop/utcp-wt/m3-stock-gen6-campaign-n23` | `51275ccd` | `936443bdcefc7b0fec594ca4aa4668c006514459bc8c000628faa3c3e8ec007e` | `756801202d5f02a94c91714cf9801827025b68f4fe9dd64cd0e012dab2cc7e87` | 1,000,000 distinct seeds; 999,998 `ok`, 2 genuine `inflight` at 572545 and 969096; zero process failures | 2,000 registered + 2 extra failures, all 2,002 matched; 2,002 JSON traces and 8,008 hashed PCAPs | 996,396 complete, 3,328 partial, 274 no payload, 2 failed |
| Corrected `~/Desktop/utcp-wt/m3-stock-gen6-fixed-n23` | `fc468295` | `9a93d8164ce09a84b7f60eba13dd1a462a5f7e024ce14ef77645f0ffccd6a264` | `539a76ad1fda31ebd284b6a2954ba8172cb904f741205773102e4fcaf7e326a5` | 1,000,000 distinct seeds; 1,000,000 `ok`; zero checker/process failures | 2,000 registered, all matched; 2,000 JSON traces and 8,000 hashed PCAPs | 996,398 complete, 3,328 partial, 274 no payload |

The independent scanner (SHA-256 `3dd6430775008acbaccd0f094c8894ab1528c64ef7e7cb1290079bedd600eab5`) read all 1,000 receipt-bound gzip shards in each campaign in seed order, checked every row's identity/profile/digest and every shard's SHA-256 and verdict counts, then checked all replay result equivalence (excluding only wall time), scenario identity, repeated failure output, trace JSON, PCAP headers, file size/hash receipts, directory coverage, and summary agreement. It found no missing, duplicate, extra, or process-failure rows. The frozen original summary correctly has `passed: false`; the corrected summary has `passed: true`. No original evidence was modified. Independent scanner, rerun checker, and output logs are preserved under `~/Desktop/utcp-wt/m3-stock-gen6-independent-evidence-n23/`.

The campaign binary SHA-256 is `fb7be5c118b471926ce7c94ad126f9188975ecbfc2bffc4373bd35e2ab483bd4` before the fix and `1474183a23cf948f2650d354aba46e4e7236b4636544c562a461b907f9cf9ad0` after it; each plan contains its binary hash. The independent GCC 15 `gcc-sweep` build of the exact corrected commit produced `fb09015e3c781acda9b32f64b18fa751f428ca3fb30293350bebaaef1065dca8`. Both binaries embed their different absolute worktree paths, so their byte hashes cannot establish equivalence; the independent sample outputs matched the fixed campaign's deterministic fields.

## Independent execution

- `gcc-sweep` `utcp_unit_tests`: 891/891 passed, two tests disabled. The focused `RecoveryTlpProbe.*` regression: 3/3 passed.
- `gcc-sweep` simulator corpus: 20/20 passed.
- Independent generated and serialized runs matched fixed primary results for seeds 0, 500, 572545, 969096, and 999500. For the former failures 572545 and 969096, the serialized input was the *original pre-fix scenario file*. Both now returned `ok` with fixed-campaign deterministic digests. The independent rerun checker SHA-256 is `16bdc7fd8c0ff1bee576b8b5080e8dee6d3b990878dc4ca63ba84cefe2602334`.
- TShark decoded all four PCAPs for each of fixed seeds 0, 500, 999500 and original failure seeds 572545, 969096 (20 files, every file had packets). `tshark_expert.sh` reported zero Error-severity items; it recorded 16 “Previous segment(s) not captured” warnings at capture starts. The development full-campaign TShark logs and exit files were also inspected: 8,008 original and 8,000 corrected captures, all exit 0 and no Error-severity items.
- Independent GCC 15 ASan/UBSan build with leak and undefined-behavior checks: focused `RecoveryTlpProbe.*` passed 3/3. The full sanitizer unit suite was launched separately and is not used for this verdict.

## Verdict and limits

Proposed promotion commit `1cbc15e` inherits corrected code verdict **3A PASS** for the original stock Gen6 million-seed campaign. It inherits **3B PASS** for 2,000 registered serialized replays with traces and four captures each, plus direct repaired reruns of both former failure scenarios. The frozen pre-fix campaign remains **3A FAIL / 3B PASS** as separate provenance; its two genuine `inflight` failures are preserved.

This report covers the stock Gen6 campaign at `fc468295`, not arbitrary-input fuzzing or promotion to `main`. TShark expert analysis was sampled (20 captures); structural and cryptographic receipt checks covered every campaign capture. The three observed delivery categories for corrected `ok` rows are separately reported; `partial` and `no_payload` are legal campaign outcomes, not checker failures.
