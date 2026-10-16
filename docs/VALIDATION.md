# Validation, reproduction, and limits

## Recorded campaign

The software suite completed 100,000 groups of 256,000 distinct 128-bit keys.
The ten frozen configurations contain 10,000 groups each.
The published result is tied to commit `cbdc97bbae8ecab66e9008a6622152741c31cb85` in the original evidence archive.
Complete per-case records and raw input files are not published in this source release.

| Conflict statistic | Value |
|---|---:|
| Minimum | 118 |
| Mean | 173.7251 |
| Median | 174 |
| p95 | 197 |
| p99 | 208 |
| p99.9 | 219 |
| Maximum | 235 |

Quantiles use the nearest-rank definition.
All 17,372,510 recorded conflicts were capacity spills.
Rejected insertions, zero-tag spills, and signature-conflict spills were zero in this suite.
Those unobserved categories remain possible, as the preserved development tests demonstrate.

The workers recorded 25,600,000,000 member queries and 409,600,000 verified nonmember probes.
They also recorded 99,700,000 duplicate-insertion checks.
These totals are semantic coverage, not independent workload trials or hardware throughput.

## Configuration meaning

| Family | Variant 0 | Variant 1 |
|---|---|---|
| random | SHAKE256 distinct keys | Same generator with independent seeds |
| nowrap | Step 1, without wrapping | Step 1 + low64(parameter), without wrapping |
| odd_mod | Odd step modulo 2^128 | Same generator with independent seeds |
| bits | Step 2^0, without wrapping | Step 2^110, without wrapping |
| even_mod | Odd parameter shifted by 1 | Odd parameter shifted by 110 |

The family names describe self-built inputs.
They do not assert that these inputs match the distribution of Huawei business keys.
No pooled reliability confidence guarantee is inferred from zero failures.

## Known boundary

Fix L = 0 and f = 1.
For q = 0 through 513, define K_q = P^(-1)((q << 64) | (1 << 14)).
The permutation makes these keys distinct, but they share one main signature.
The first key occupies the main representation.
The next 512 keys fill exact overflow. The final key is rejected.
The expected result is 513 conflicts and one rejection.
All 513 accepted keys remain queryable; the rejected key is absent.

The boundary input SHA256 is `849719b7c5719201f15230a4b52cdf044dd56d05ae710b0253b7b76fe5336c04`.
It is excluded from the statistical suite.
More random tests cannot remove this counterexample to arbitrary-input conflict bounds.

## Scope of the original independent review

The local review checked 303,033 archive files and linked every saved case to its original plan and worker report.
It also checked all result CSV rows, totals, strata, and quantiles.
It parsed the 20 retained formal input files and four interrupted input files.
It did not regenerate the other 99,980 inputs or rerun the recorded member queries locally.

One session was interrupted. Four incomplete attempts resumed with the same input hashes.
Those attempts are not additional completed groups or substituted seeds.
The original run records two CPU models, so elapsed times are not a controlled CPU comparison.

The original RTL trace contains 44,286 operations and seven resets.
Six proof-success logs cover stated subproblems.
The control proof uses semantic cutpoints and is not full-memory semantic induction.
No full-scale RTL campaign across all 100,000 groups was performed.

## Reproduction choices

The root README gives commands for a recorded group and the known boundary.
These commands run only on native Linux with assertions enabled.
The case helper reconstructs original keys from the recorded seed and checks the original input hash.
It never chooses a new seed.
If you separately hold the recorded binary, pass `--input` to read original group 0 directly.
If you separately hold the per-case CSV, use `--records` to select another original group.
Those data files are not part of the public source download.

## Full preserved gates

Install native Icarus Verilog, vvp, and Yosys before running the original gate entry.
The recorded gate used Icarus Verilog 11.0 and Yosys 0.23.
Use a new absolute result directory outside this repository, with no spaces in its path.

```text
python3 -B frozen/run_cloud.py --output /tmp/exact128-full-gates-new
```

This runner compiles RTL, checks proofs and generic storage, and runs fixed development tests.
After its gates pass, it creates ten new self-built cases.
It does not replay or extend the original 100,000-group campaign.
This public packaging has not rerun that full gate sequence.
All preserved algorithm, gate-runner, testbench, and harness files retain their original bytes.
Only the packaging verifier and source manifest have new identities inside frozen/.

## Remaining evidence

Huawei-designated inputs and representative business data remain required.
Same-budget alternatives, controlled component comparisons, full-scale RTL, and target-device measurements remain open.
There is no supported claim of whole-algorithm originality, theoretical optimality, or official acceptance.
