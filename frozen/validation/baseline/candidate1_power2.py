"""Candidate 1 power-of-two XOR4: immutable two-choice placement and exact one-record routing.

The hash is a literal chain of twenty-four fixed-width primitives. Main memory has
thirteen byte banks sharing one record address. This is a functional resource
model, not measured RTL or vendor-memory compliance.
"""

from dataclasses import dataclass
import struct


WIDTH = 256
MASK256 = (1 << WIDTH) - 1
MASK128 = (1 << 128) - 1
C1 = 0x9E3779B97F4A7C15D1B54A32D192ED03
C2 = 0xD6E8FEB86659FD9394D049BB133111EB
C3 = 0xA24BAED4963EE4079FB21C651E98DF25
C4 = 0xDB4F0B9175AE2165BBE0563303A4615F
MULTIPLIERS = (C1, C2, C3, C4)
ROTATIONS = (37, 73, 29, 91)
XOR_CONSTANTS = (0xE1D86738A4C7AD2448E183A5C314C87E,
                 0x977872700329217BDBDB36DC65388ECD,
                 0x533F9F78FD7509F0FE5E78EE66FB2CA3,
                 0x85BA24B712CECE43CF4EF5D0DB781BC2)
DUPLICATE = (1 << 128) + 1
HASH_PIPELINE = tuple(stage for constant, xor_constant, rotation in zip(MULTIPLIERS, XOR_CONSTANTS, ROTATIONS) for stage in (
    ('multiply_constant', constant), ('and_constant', MASK128), ('xor_constant', xor_constant),
    ('multiply_constant', DUPLICATE), ('shift_right_constant', rotation),
    ('and_constant', MASK128)))
B = 1 << 14
CAP = 9
FBITS = 14
FMASK = (1 << FBITS) - 1
RECORD_BITS = 128 - 28
RBITS = RECORD_BITS
MAIN_USED_ROWS = 2 * B * CAP
MAIN_DEPTH = (1 << 18) + (1 << 15)
AUX_DEPTH = B
OVERFLOW_CAP = 512
STATE_BYTES = 1024
LEFT_ADDRESS_PIPELINE = HASH_PIPELINE + (('and_constant', (1 << 14) - 1),)
RIGHT_ADDRESS_PIPELINE = HASH_PIPELINE + (('and_constant', (1 << 28) - 1),
    ('multiply_constant', (1 << 14) + 1), ('shift_right_constant', 14),
    ('and_constant', (1 << 14) - 1))


def transform(key):
    """Python emulates modulo-2^256 primitive outputs; no data-dependent loop."""
    state = key
    for operation, constant in HASH_PIPELINE:
        if operation == 'multiply_constant':
            state = state * constant & MASK256
        elif operation == 'and_constant':
            state &= constant
        elif operation == 'xor_constant':
            state ^= constant
        else:
            state >>= constant
    return state


def rotate128(value, rotation):
    """Test/proof notation, not an extra atomic operation in the datapath."""
    return ((value >> rotation) | (value << (128 - rotation))) & MASK128


def inverse_transform(value):
    """Harness helper only; not used during insertion or query."""
    for constant, xor_constant, rotation in reversed(tuple(zip(MULTIPLIERS, XOR_CONSTANTS, ROTATIONS))):
        value = (rotate128(value, 128 - rotation) ^ xor_constant) * pow(constant, -1, 1 << 128) & MASK128
    return value


def encode(value):
    left = value & (B - 1)
    fingerprint = value >> 14 & FMASK
    right = ((left + fingerprint) & (B - 1)) + B
    return left, right, fingerprint, value >> 28


def reconstruct(record, left, fingerprint):
    return (record << 28) | (fingerprint << 14) | left


@dataclass
class Access:
    main_reads: int = 0
    main_writes: int = 0
    aux_reads: int = 0
    aux_writes: int = 0
    cam_searches: int = 0
    cam_writes: int = 0

    def verify(self):
        assert self.main_reads <= 1 and self.main_writes <= 1
        assert self.aux_reads <= 2 and self.aux_writes <= 1
        assert self.cam_searches == 1 and self.cam_writes <= 1


class Dictionary:
    def __init__(self):
        # One byte from each bank forms one 104-bit record. All banks receive
        # the same row address and one common read/write command.
        self.main_banks = tuple(bytearray(MAIN_DEPTH) for _ in range(13))
        self.aux_banks = tuple(bytearray(AUX_DEPTH * 16) for _ in range(2))
        self.overflow = bytearray(OVERFLOW_CAP * 16)
        self.state = bytearray(STATE_BYTES)
        self.state[8:24] = C1.to_bytes(16, 'little')
        self.state[24:40] = C2.to_bytes(16, 'little')
        self.state[40:57] = DUPLICATE.to_bytes(17, 'little')
        self.state[96:112] = C3.to_bytes(16, 'little')
        self.state[112:128] = C4.to_bytes(16, 'little')
        self.state[128:132] = bytes(ROTATIONS)
        for index, constant in enumerate(XOR_CONSTANTS):
            self.state[160 + 16 * index:176 + 16 * index] = constant.to_bytes(16, 'little')
        struct.pack_into('<IIIIIIII', self.state, 64,
                         B, CAP, FBITS, RBITS, OVERFLOW_CAP, MAIN_DEPTH, AUX_DEPTH, WIDTH)

    @property
    def overflow_count(self):
        return struct.unpack_from('<I', self.state, 0)[0]

    @property
    def rejected_count(self):
        return struct.unpack_from('<I', self.state, 4)[0]

    def _cam_contains(self, key, access):
        access.cam_searches += 1
        used = self.overflow_count * 16
        needle = key.to_bytes(16, 'little')
        offset = self.overflow.find(needle, 0, used)
        # Functional CAM emulator. Cross-record substring matches are ignored.
        # The number of candidate byte offsets is bounded by 8192.
        for _ in range(OVERFLOW_CAP * 16):
            if offset < 0:
                return False
            if offset % 16 == 0:
                return True
            offset = self.overflow.find(needle, offset + 1, used)
        raise AssertionError('CAM emulator bound exceeded')

    def _overflow_insert(self, key, cause, access):
        count = self.overflow_count
        if count == OVERFLOW_CAP:
            struct.pack_into('<I', self.state, 4, self.rejected_count + 1)
            return 'rejected_' + cause
        self.overflow[count * 16:(count + 1) * 16] = key.to_bytes(16, 'little')
        struct.pack_into('<I', self.state, 0, count + 1)
        access.cam_writes += 1
        return 'overflow_' + cause

    def _read_aux(self, bucket, access):
        access.aux_reads += 1
        side = int(bucket >= B)
        row = bucket - side * B
        return int.from_bytes(self.aux_banks[side][row * 16:(row + 1) * 16], 'little')

    @staticmethod
    def _matching_slots(word, fingerprint):
        assert fingerprint != 0
        return [slot for slot in range(CAP)
                if word >> (slot * FBITS) & FMASK == fingerprint]

    @staticmethod
    def _occupied_count(word):
        # Nine bounded tests emulate a prefix occupancy circuit. The primitive
        # implementation is defined separately in power2_datapath.py.
        tags = [(word >> (slot * FBITS)) & FMASK for slot in range(CAP)]
        count = sum(tag != 0 for tag in tags)
        assert all(tags[slot] != 0 for slot in range(count))
        assert all(tags[slot] == 0 for slot in range(count, CAP))
        return count

    def _locate(self, left, right, fingerprint, access):
        lw, rw = self._read_aux(left, access), self._read_aux(right, access)
        matches = [(left, slot) for slot in self._matching_slots(lw, fingerprint)]
        matches += [(right, slot) for slot in self._matching_slots(rw, fingerprint)]
        assert len(matches) <= 1, 'more than one main record has this signature'
        return lw, rw, matches

    def _read_main(self, bucket, slot, access):
        access.main_reads += 1
        address = bucket * CAP + slot
        return int.from_bytes(bytes(bank[address] for bank in self.main_banks), 'little')

    def _write_main(self, bucket, slot, record, access):
        access.main_writes += 1
        address = bucket * CAP + slot
        for bank, byte in zip(self.main_banks, record.to_bytes(13, 'little')):
            bank[address] = byte

    def contains(self, key):
        assert 0 <= key <= MASK128
        access = Access()
        if self._cam_contains(key, access):
            access.verify()
            return True, access
        value = transform(key)
        left, right, fingerprint, _ = encode(value)
        if fingerprint == 0:
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
            access.verify()
            return 'duplicate', access
        value = transform(key)
        left, right, fingerprint, record = encode(value)
        if fingerprint == 0:
            result = self._overflow_insert(key, 'zero_fingerprint', access)
            access.verify()
            return result, access
        lw, rw, matches = self._locate(left, right, fingerprint, access)
        if matches:
            old = self._read_main(*matches[0], access)
            if reconstruct(old, left, fingerprint) == value:
                result = 'duplicate'
            else:
                result = self._overflow_insert(key, 'signature', access)
        else:
            nl, nr = self._occupied_count(lw), self._occupied_count(rw)
            if nl == CAP and nr == CAP:
                result = self._overflow_insert(key, 'capacity', access)
            else:
                if nl <= nr:
                    bucket, count, word = left, nl, lw
                else:
                    bucket, count, word = right, nr, rw
                self._write_main(bucket, count, record, access)
                word |= fingerprint << (count * FBITS)
                side = int(bucket >= B)
                row = bucket - side * B
                self.aux_banks[side][row * 16:(row + 1) * 16] = word.to_bytes(16, 'little')
                access.aux_writes += 1
                result = 'main'
        access.verify()
        return result, access

    def storage(self, n=256000):
        fields = {
            'main_bits': sum(len(bank) for bank in self.main_banks) * 8,
            'auxiliary_bits': sum(len(bank) for bank in self.aux_banks) * 8,
            'overflow_bits': len(self.overflow) * 8,
            'state_bits': len(self.state) * 8,
        }
        total = sum(fields.values())
        return dict(fields, total_bits=total, ratio=total / (128 * n),
                    within_modeled_budget=10 * total <= 11 * 128 * n,
                    hash_primitive_chain_defined=True, full_datapath_audited=False,
                    byte_bank_layout_defined=True, vendor_hardware_validated=False)
