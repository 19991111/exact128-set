# Exact128 Set

Exact membership for full 128-bit keys, with online insertion and a constrained storage interface.

[中文说明](README.zh-CN.md) | [Algorithm](docs/ALGORITHM.md) | [Validation and limits](docs/VALIDATION.md) | [Source identity](docs/SOURCE_IDENTITY.md)

The published candidate is **huawei128_wide50_w128_aux512_v1r4**.
The implementation and RTL retain the frozen bytes used by the recorded validation.
This repository contains one delivery version and its required verification helpers.

## Start here

| File | Purpose |
|---|---|
| `frozen/reference.py` | Self-contained Python specification of the exact set |
| `frozen/rtl/` | Hash chains, serialized controller, and modeled memories |
| `frozen/validation/` | RTL testbench, proof harnesses, and validation-only reference dependencies |
| `frozen/run_cloud.py` | Preserved full native-Linux gate runner |
| `cases.py` | Preserved worker and constructed boundary from the supplemental suite |
| `tools/verify_release.py` | Read-only hashes, syntax, source identity, and summary checks |
| `tools/reproduce.py` | Reproduce one recorded group or the known boundary on Linux |
| `evaluation/` | Small summaries and one recorded group's expected result |

The `validation/baseline/` files are dependencies of the preserved gate runner.
They are not alternative recommended versions.
Large experiment records and recorded input downloads are release assets.
No earlier development history is imported.

## Verify the download

Python 3.10 or newer is required. Integrity checks work on Windows and Linux.

```text
python -B tools/verify_release.py
```

This command checks files and syntax without importing the algorithm.
It does not generate keys or seeds.

## Reproduce a recorded group on native Linux

Python 3.10 or newer and enabled assertions are required. Do not use `python -O`.
The following command reconstructs the original group 0 from its saved seed.
It verifies the original input hash and all saved semantic counters.

```text
python3 -B tools/reproduce.py --case-id 0 --output /tmp/exact128-case0.json
python3 -B tools/reproduce.py --boundary --output /tmp/exact128-boundary.json
```

Output files must not already exist. Results remain outside the repository.
The boundary command succeeds when it reproduces the expected rejection.
It is a regression check of a known limitation, not a passing statistical group.

Download the [release assets](https://github.com/19991111/exact128-set/releases/tag/v1r4-source) for the recorded binary input and all 100,000 per-group records.
The complete CSV contains each original seed and input hash.
To reproduce another saved group, provide the downloaded CSV and one group identifier:

```text
python3 -B tools/reproduce.py --case-id 53776 --records /tmp/v1r4-100k-per-case.csv.gz --output /tmp/exact128-case53776.json
```

The helper runs only the selected group. It does not start a new 100,000-group campaign.

## Recorded software result

| Measure | Recorded outcome |
|---|---:|
| Groups | 100,000 |
| Distinct keys per group | 256,000 |
| Configurations | 10, with 10,000 groups each |
| Failed groups / rejected insertions | 0 / 0 |
| Conflicts: minimum / mean / maximum | 118 / 173.7251 / 235 |
| Conflict limit per group | 512 |
| Maximum conflict rate | 0.091796875% |
| Charged storage | 109.025% of the raw-key baseline |

These are self-built software-model results.
Huawei-designated inputs, business data, and target-device measurements remain open.
All recorded conflicts in this suite were capacity spills.
Operation totals are coverage counts, not hardware throughput.

## Known boundary

A separate 514-key construction produces **513 conflicts and one rejected insertion**.
The accepted keys remain queryable.
The design therefore has no arbitrary-input conflict guarantee.
See [the construction and interpretation](docs/VALIDATION.md#known-boundary).

## Source and evidence identity

- Frozen candidate source: `133211a2efe88a1403e3d80d6e83007248936359`.
- Recorded 100,000-group result: `cbdc97bbae8ecab66e9008a6622152741c31cb85`.
- Publication tag: [`v1r4-source`](https://github.com/19991111/exact128-set/tree/v1r4-source).
- Per-file mappings and hashes: `SOURCE_PROVENANCE.json`.

Only the packaging verifier and manifest use new identities inside `frozen/`.
Algorithm, RTL, and preserved gate sources are byte-identical to their source mapping.
Full gate execution for this selected public packaging has not been repeated.
The repository CI checks integrity, recorded group 0, and the known boundary on Linux.

This is an independent technical artifact. It does not claim official Huawei acceptance or endorsement.
No new reuse license is granted by this publication. See [NOTICE](NOTICE.md).
