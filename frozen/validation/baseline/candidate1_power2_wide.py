"""Separate 50-bit fingerprint proposal. The frozen v1 is not modified.

The Python code emulates fixed-width circuits. Each auxiliary command reads
one 456-bit word. Each main command reads or writes one aligned 128-bit word.
The proposal requires the official 512-bit matching-width interpretation;
it does not meet the earlier self-imposed 128-bit auxiliary-word constraint.
There is no RTL implementation or target-memory certification for this file.
"""

import struct

import candidate1_power2 as base
from candidate1_power2 import Access, MASK128, MASK256, transform, inverse_transform
from candidate1_power2_exact import InsertResult, RTL_STATUS

B = base.B
CAP = base.CAP
FBITS = 50
FMASK = (1 << FBITS) - 1
RBITS = 64
AUX_BYTES = 57
AUX_BITS = 8 * AUX_BYTES
COUNT_SHIFT = CAP * FBITS
TAG_MASK = (1 << COUNT_SHIFT) - 1
COUNT_MASK = 15 << COUNT_SHIFT
MASK512 = (1 << 512) - 1
MAIN_RECORDS = 2 * B * CAP
MAIN_WORDS = MAIN_RECORDS // 2
OVERFLOW_CAP = base.OVERFLOW_CAP
STATE_BYTES = base.STATE_BYTES
REPEAT = sum(1 << (FBITS * slot) for slot in range(CAP))
LOW = sum(((1 << (FBITS - 1)) - 1) << (FBITS * slot) for slot in range(CAP))
HIGH = sum(1 << (FBITS * slot + FBITS - 1) for slot in range(CAP))
SLOT_CODE = sum(slot << (FBITS * (CAP - 1 - slot)) for slot in range(CAP))


def encode(value):
    left = value & (B - 1)
    fingerprint = (value >> 14) & FMASK
    right = B + ((left + (fingerprint & (B - 1))) & (B - 1))
    return left, right, fingerprint, value >> 64


def reconstruct(record, left, fingerprint):
    return (record << 64) | (fingerprint << 14) | left


def zero_mask(word):
    low = word & LOW
    added = (low + LOW) & MASK512
    combined = added | word
    return (combined ^ MASK512) & HIGH


def match_slot(word, fingerprint):
    broadcast = (fingerprint * REPEAT) & MASK512
    mask = zero_mask(word ^ broadcast)
    weighted = (mask * SLOT_CODE) & MASK512
    slot = (weighted >> (COUNT_SHIFT - 1)) & 15
    present = (((mask - 1) & MASK512) >> 511) ^ 1
    return slot, present


def occupancy_count(word):
    return (word >> COUNT_SHIFT) & 15


def append_fingerprint(word, count, fingerprint):
    return (word & TAG_MASK) | (fingerprint << (count * FBITS)) | ((count + 1) << COUNT_SHIFT)


class Dictionary(base.Dictionary):
    def __init__(self):
        # Two 64-bit records occupy the two halves of one aligned main word.
        self.main_words = bytearray(MAIN_WORDS * 16)
        self.aux_banks = tuple(bytearray(B * AUX_BYTES) for _ in range(2))
        self.overflow = bytearray(OVERFLOW_CAP * 16)
        self.state = bytearray(STATE_BYTES)
        self.state[8:24] = base.C1.to_bytes(16, 'little')
        self.state[24:40] = base.C2.to_bytes(16, 'little')
        self.state[40:57] = base.DUPLICATE.to_bytes(17, 'little')
        self.state[96:112] = base.C3.to_bytes(16, 'little')
        self.state[112:128] = base.C4.to_bytes(16, 'little')
        self.state[128:132] = bytes(base.ROTATIONS)
        for index, constant in enumerate(base.XOR_CONSTANTS):
            self.state[160 + 16 * index:176 + 16 * index] = constant.to_bytes(16, 'little')
        struct.pack_into('<IIIIIIII', self.state, 64,
                         B, CAP, FBITS, RBITS, OVERFLOW_CAP, MAIN_WORDS, B, 512)
        # Charge all matching constants and masks. No selection table, input
        # seed, oracle, or future key is stored in the dictionary.
        constants = (REPEAT, LOW, HIGH, SLOT_CODE, MASK512, TAG_MASK, COUNT_MASK)
        for index, constant in enumerate(constants):
            self.state[240 + 64 * index:304 + 64 * index] = constant.to_bytes(64, 'little')
        self.state[688:704] = MASK128.to_bytes(16, 'little')
        self.state[704:736] = MASK256.to_bytes(32, 'little')
        # Bytes 736..1023 remain charged for finite controller/register state.
        # Complete RTL state accounting is still required.

    @property
    def conflict_count(self):
        return self.overflow_count + self.rejected_count

    def _read_aux(self, bucket, access):
        access.aux_reads += 1
        side = int(bucket >= B)
        row = bucket - side * B
        start = row * AUX_BYTES
        return int.from_bytes(self.aux_banks[side][start:start + AUX_BYTES], 'little')

    def _locate(self, left, right, fingerprint, access):
        lw, rw = self._read_aux(left, access), self._read_aux(right, access)
        ls, lp = match_slot(lw, fingerprint)
        rs, rp = match_slot(rw, fingerprint)
        assert not (lp and rp), 'More than one main record has this signature.'
        matches = [(left, ls)] if lp else ([(right, rs)] if rp else [])
        return lw, rw, matches

    def _read_main_word(self, bucket, slot, access):
        access.main_reads += 1
        record_address = bucket * CAP + slot
        start = (record_address >> 1) * 16
        return int.from_bytes(self.main_words[start:start + 16], 'little'), record_address & 1

    def _read_main(self, bucket, slot, access):
        word, half = self._read_main_word(bucket, slot, access)
        return (word >> (half << 6)) & ((1 << 64) - 1)

    def _write_fresh_main(self, bucket, slot, record, access):
        # The only main read on a fresh insertion preserves the other half.
        old, half = self._read_main_word(bucket, slot, access)
        shift = half << 6
        mask = ((1 << 64) - 1) << shift
        updated = (old & (MASK128 ^ mask)) | (record << shift)
        start = ((bucket * CAP + slot) >> 1) * 16
        self.main_words[start:start + 16] = updated.to_bytes(16, 'little')
        access.main_writes += 1

    def contains(self, key):
        assert 0 <= key <= MASK128
        access = Access()
        if self._cam_contains(key, access):
            access.verify()
            return True, access
        value = transform(key)
        left, right, fingerprint, _ = encode(value)
        if not fingerprint:
            access.verify()
            return False, access
        _, _, matches = self._locate(left, right, fingerprint, access)
        found = False
        if matches:
            record = self._read_main(*matches[0], access)
            found = reconstruct(record, left, fingerprint) == value
        access.verify()
        return found, access

    def insert(self, key):
        assert 0 <= key <= MASK128
        access = Access()
        if self._cam_contains(key, access):
            outcome = 'duplicate'
        else:
            value = transform(key)
            left, right, fingerprint, record = encode(value)
            if not fingerprint:
                outcome = self._overflow_insert(key, 'zero_fingerprint', access)
            else:
                lw, rw, matches = self._locate(left, right, fingerprint, access)
                if matches:
                    old = self._read_main(*matches[0], access)
                    if reconstruct(old, left, fingerprint) == value:
                        outcome = 'duplicate'
                    else:
                        outcome = self._overflow_insert(key, 'signature', access)
                else:
                    nl, nr = occupancy_count(lw), occupancy_count(rw)
                    assert 0 <= nl <= CAP and 0 <= nr <= CAP
                    if nl == CAP and nr == CAP:
                        outcome = self._overflow_insert(key, 'capacity', access)
                    else:
                        if nl <= nr:
                            bucket, count, word = left, nl, lw
                        else:
                            bucket, count, word = right, nr, rw
                        self._write_fresh_main(bucket, count, record, access)
                        updated = append_fingerprint(word, count, fingerprint)
                        side = int(bucket >= B)
                        row = bucket - side * B
                        start = row * AUX_BYTES
                        self.aux_banks[side][start:start + AUX_BYTES] = updated.to_bytes(AUX_BYTES, 'little')
                        access.aux_writes += 1
                        outcome = 'main'
        access.verify()
        status = RTL_STATUS[outcome]
        return InsertResult(2 <= status <= 6, status == 3, 4 <= status <= 9,
                            outcome, status, access)

    def storage(self, n=256000):
        fields = {
            'main_bits': len(self.main_words) * 8,
            'auxiliary_bits': sum(len(bank) for bank in self.aux_banks) * 8,
            'overflow_bits': len(self.overflow) * 8,
            'state_bits': len(self.state) * 8,
        }
        total = sum(fields.values())
        return dict(fields, total_bits=total, ratio=total / (128 * n),
                    profile='power2_wide_proposal',
                    within_modeled_budget=10 * total <= 11 * 128 * n,
                    main_command_bits=128, auxiliary_command_bits=AUX_BITS,
                    requires_512_bit_auxiliary_matching_interpretation=True,
                    RTL_implemented=False, controller_state_budget_verified=False,
                    vendor_hardware_validated=False, official_contract_confirmed=False)
