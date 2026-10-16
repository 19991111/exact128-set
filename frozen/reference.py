"""Exact 128-bit set model for the Huawei delivery candidate.

This model specifies semantics and interface commands. Python object overhead
and execution time are not hardware measurements. Native validation is Linux-only.
"""
from dataclasses import dataclass
import struct

B = 16384
CAP = 9
F_BITS = 50
F_MASK = (1 << F_BITS) - 1
MASK128 = (1 << 128) - 1
MASK256 = (1 << 256) - 1
MASK64 = (1 << 64) - 1
MAIN_RECORDS = 2 * B * CAP
MAIN_WORDS = MAIN_RECORDS // 2
AUX_BYTES = 64
OVERFLOW_CAP = 512
STATE_BYTES = 1024
MULTIPLIERS = (0x9E3779B97F4A7C15D1B54A32D192ED03,
               0xD6E8FEB86659FD9394D049BB133111EB,
               0xA24BAED4963EE4079FB21C651E98DF25,
               0xDB4F0B9175AE2165BBE0563303A4615F)
XORS = (0xE1D86738A4C7AD2448E183A5C314C87E,
        0x977872700329217BDBDB36DC65388ECD,
        0x533F9F78FD7509F0FE5E78EE66FB2CA3,
        0x85BA24B712CECE43CF4EF5D0DB781BC2)
ROTATIONS = (37, 73, 29, 91)


def transform(key):
    assert 0 <= key <= MASK128
    value = key
    for multiplier, xor, rotation in zip(MULTIPLIERS, XORS, ROTATIONS):
        value = (value * multiplier) & MASK256
        value &= MASK128
        value ^= xor
        value = (value * ((1 << 128) + 1)) & MASK256
        value >>= rotation
        value &= MASK128
    return value


def inverse_transform(value):
    """Validation helper; never used by an insertion or a query."""
    for multiplier, xor, rotation in reversed(tuple(zip(MULTIPLIERS, XORS, ROTATIONS))):
        value = ((value << rotation) | (value >> (128 - rotation))) & MASK128
        value = ((value ^ xor) * pow(multiplier, -1, 1 << 128)) & MASK128
    return value


def encode(value):
    left = value & (B - 1)
    fingerprint = (value >> 14) & F_MASK
    right = ((left + (fingerprint & (B - 1))) & (B - 1)) + B
    return left, right, fingerprint, value >> 64


def reconstruct(record, left, fingerprint):
    return (record << 64) | (fingerprint << 14) | left


@dataclass
class Access:
    main_reads: int = 0
    main_writes: int = 0
    aux_reads: int = 0
    aux_writes: int = 0
    cam_searches: int = 0
    cam_writes: int = 0

    def verify(self):
        assert 0 <= self.main_reads <= 1 and 0 <= self.main_writes <= 1
        assert 0 <= self.aux_reads <= 2 and 0 <= self.aux_writes <= 1
        assert self.cam_searches == 1 and 0 <= self.cam_writes <= 1


class Dictionary:
    def __init__(self):
        self.main = bytearray(MAIN_WORDS * 16)
        self.aux = (bytearray(B * AUX_BYTES), bytearray(B * AUX_BYTES))
        self.overflow = bytearray(OVERFLOW_CAP * 16)
        self.state = bytearray(STATE_BYTES)
        # Half of the reserved state is charged to fixed parameters/constants.
        struct.pack_into('<8I', self.state, 64, B, CAP, F_BITS, 64,
                         OVERFLOW_CAP, MAIN_WORDS, AUX_BYTES * 8, STATE_BYTES)
        for i, constant in enumerate(MULTIPLIERS + XORS):
            self.state[128 + 16*i:144 + 16*i] = constant.to_bytes(16, 'little')
        self.state[256:260] = bytes(ROTATIONS)
        self.state[272:304] = ((1 << 128) + 1).to_bytes(32, 'little')
        self.state[304:336] = MASK256.to_bytes(32, 'little')
        self.state[336:352] = MASK128.to_bytes(16, 'little')

    @property
    def overflow_count(self):
        return struct.unpack_from('<I', self.state, 0)[0]

    @property
    def rejected_count(self):
        return struct.unpack_from('<I', self.state, 4)[0]

    @property
    def conflict_count(self):
        return self.overflow_count + self.rejected_count

    def _cam(self, key, access):
        access.cam_searches += 1
        needle = key.to_bytes(16, 'little')
        limit = self.overflow_count * 16
        offset = self.overflow.find(needle, 0, limit)
        while offset >= 0:
            if offset % 16 == 0:
                return True
            offset = self.overflow.find(needle, offset + 1, limit)
        return False

    def _aux_word(self, bucket, access):
        access.aux_reads += 1
        side, row = divmod(bucket, B)
        offset = row * AUX_BYTES
        return int.from_bytes(self.aux[side][offset:offset+AUX_BYTES], 'little')

    @staticmethod
    def _slot(word, fingerprint):
        # Independent scalar specification of nine parallel hardware equalities.
        count = (word >> 450) & 15
        assert count <= CAP and word >> 454 == 0
        slots = [i for i in range(CAP)
                 if ((word >> (i*F_BITS)) & F_MASK) == fingerprint]
        assert len(slots) <= 1
        if slots:
            assert slots[0] < count
            return slots[0]
        return None

    def _locate(self, left, right, fingerprint, access):
        lw, rw = self._aux_word(left, access), self._aux_word(right, access)
        ls, rs = self._slot(lw, fingerprint), self._slot(rw, fingerprint)
        assert ls is None or rs is None, 'A signature must route to one record.'
        match = (left, ls) if ls is not None else ((right, rs) if rs is not None else None)
        return lw, rw, match

    def _read(self, bucket, slot, access):
        access.main_reads += 1
        address = bucket * CAP + slot
        offset = (address >> 1) * 16
        word = int.from_bytes(self.main[offset:offset+16], 'little')
        return word, address & 1

    def _spill(self, key, reason, access):
        count = self.overflow_count
        if count == OVERFLOW_CAP:
            struct.pack_into('<I', self.state, 4, self.rejected_count + 1)
            return 7 + reason
        self.overflow[16*count:16*(count+1)] = key.to_bytes(16, 'little')
        struct.pack_into('<I', self.state, 0, count + 1)
        access.cam_writes += 1
        return 4 + reason

    def contains(self, key):
        assert 0 <= key <= MASK128
        access = Access()
        if self._cam(key, access):
            access.verify()
            return True, access
        value = transform(key)
        left, right, f, _ = encode(value)
        found = False
        if f:
            _, _, match = self._locate(left, right, f, access)
            if match is not None:
                word, half = self._read(*match, access)
                record = (word >> (64*half)) & MASK64
                found = reconstruct(record, left, f) == value
        access.verify()
        return found, access

    def insert(self, key):
        assert 0 <= key <= MASK128
        access = Access()
        if self._cam(key, access):
            status = 3
        else:
            value = transform(key)
            left, right, f, record = encode(value)
            if not f:
                status = self._spill(key, 0, access)
            else:
                lw, rw, match = self._locate(left, right, f, access)
                if match is not None:
                    word, half = self._read(*match, access)
                    old = (word >> (half*64)) & MASK64
                    status = 3 if reconstruct(old, left, f) == value else self._spill(key, 1, access)
                else:
                    nl, nr = (lw >> 450) & 15, (rw >> 450) & 15
                    if nl == CAP and nr == CAP:
                        status = self._spill(key, 2, access)
                    else:
                        bucket, count, aux = (left, nl, lw) if nl <= nr else (right, nr, rw)
                        word, half = self._read(bucket, count, access)
                        shift = half*64
                        updated = (word & (MASK128 ^ (MASK64 << shift))) | (record << shift)
                        offset = ((bucket*CAP+count) >> 1)*16
                        self.main[offset:offset+16] = updated.to_bytes(16, 'little')
                        access.main_writes += 1
                        tags = aux & ((1 << 450)-1)
                        aux = tags | (f << (50*count)) | ((count+1) << 450)
                        side, row = divmod(bucket, B)
                        self.aux[side][row*64:(row+1)*64] = aux.to_bytes(64, 'little')
                        access.aux_writes += 1
                        status = 2
        access.verify()
        return status, access

    def storage(self):
        parts = dict(main_bits=len(self.main)*8,
                     auxiliary_bits=sum(map(len, self.aux))*8,
                     overflow_bits=len(self.overflow)*8, state_bits=len(self.state)*8)
        total = sum(parts.values())
        return dict(parts, total_bits=total, baseline_bits=256000*128,
                    ratio=total/(256000*128), within_budget=10*total <= 11*256000*128,
                    physical_chip_verified=False, official_acceptance=False)
