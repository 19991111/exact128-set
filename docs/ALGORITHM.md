# Algorithm and interface

## Object and operations

The object is an exact set of unsigned 128-bit keys.
There is no separate value field, deletion, relocation, or background rebuilding.
One request is outstanding at a time.
The Python model specifies semantics and charged accesses; its runtime is not a hardware result.

## Reversible decomposition

Four rounds apply odd multiplication modulo 2^128, XOR, and rotation.
Each operation is bijective. Constants are fixed in the source.
The transformed value is partitioned into q (64 bits), f (50 bits), and L (14 bits).
All 128 bits are retained across these fields.

Each side has 16,384 buckets with nine slots per bucket.
The left bucket is L. The right index is (L + low14(f)) modulo 16,384.
The global right bucket identifier adds 16,384.
The main representation permits at most one record for a signature (L, f).

## Query

1. Search the 512-entry exact overflow store with the original key.
2. Return present on an exact overflow hit.
3. Otherwise transform the key and derive its two buckets.
4. Return absent for f = 0 after the overflow miss.
5. Read both auxiliary words and compare the tags with f.
6. Return absent if neither bucket contains the signature.
7. Read the one main word selected by the unique matching slot.
8. Compare the selected residual with q to decide full-key equality.

The tag match alone never returns present.
The partition and bijection make the final comparison exact.

## Insertion

An exact duplicate returns duplicate without adding a conflict.
A zero tag, an existing signature with a different key, or two full buckets causes a conflict.
The key then enters the exact overflow store if space remains.
A full overflow store causes rejection and preserves the accepted set.

If neither candidate contains the signature, choose the less occupied nonfull bucket.
Break equal-load ties toward the left.
Two 64-bit residuals share one 128-bit main word.
Read-modify-write preserves the unselected half, including across odd bucket boundaries.

## Auxiliary word and access model

One auxiliary word contains nine 50-bit tags, a 4-bit count, and 58 charged padding bits.
Occupied slots are contiguous. Zero tags are not inserted into the main representation.
Queries read at most one main word.
Insertions read at most one main word and write at most one main word.
Each request reads at most two auxiliary words and writes at most one.
Each request performs one exact overflow search and at most one overflow write.

The left and right terminal chains use 24 and 28 allowed operations, respectively.
The terminal-field wiring and auxiliary interface are explicit engineering interpretations.
They remain subject to the counterpart's requirements review.
The 512-way comparison has real logic and routing costs.

## Storage accounting

| Component | Bits |
|---|---:|
| Main table | 18,874,368 |
| Auxiliary tables | 16,777,216 |
| Exact overflow | 65,536 |
| Reserved parameters and state | 8,192 |
| Total | 35,725,312 |

The baseline is 256,000 x 128 = 32,768,000 bits.
The charged ratio is 109.025%, leaving 39,936 bytes below 110%.
These figures do not establish target-device area, power, timing, or memory-macro cost.

## RTL operation

The controller accepts a command when cmd_valid and cmd_ready are both asserted.
It latches the operation and full key.
A response remains stable while rsp_valid is asserted and rsp_ready is deasserted.
Initialization clears both auxiliary banks over 16,384 cycles before accepting requests.
The caller must reinitialize before the 32-bit cumulative rejection counter overflows.

| Status | Meaning |
|---:|---|
| 0 / 1 | Query absent / present |
| 2 / 3 | Main insertion / duplicate |
| 4 / 5 / 6 | Zero-tag / signature / capacity spill |
| 7 / 8 / 9 | Zero-tag / signature / capacity rejection |

Conflict count equals overflow entries plus rejected insertion attempts.
See the preserved RTL and validation sources for the exact signal interface.
