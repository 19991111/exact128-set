"""Power-of-two dictionary using the declared fixed-width matching kernels.

The associative overflow lookup still emulates the separately declared CAM.
This module is not a measured silicon or a complete strict-chain certificate.
"""

import candidate1_power2 as base
from candidate1_power2 import *
from power2_datapath import REPEAT, LOW, HIGH, SLOT_CODE, COMPRESS


def zero_mask(word):
    low = word & LOW
    added = (low + LOW) & MASK128
    combined = (added | word) & MASK128
    inverted = combined ^ MASK128
    return inverted & HIGH


def match_slot(word, fingerprint):
    broadcast = fingerprint * REPEAT & MASK128
    differences = word ^ broadcast
    mask = zero_mask(differences)
    weighted = mask * SLOT_CODE & MASK256
    slot = (weighted >> 125) & 15
    present = (((mask - 1) & MASK128) >> 127) ^ 1
    return slot, present


def occupancy_count(word):
    free = zero_mask(word)
    packed = ((free * COMPRESS & MASK128) >> 117) & 511
    used = packed ^ 511
    half = (used >> 1) & 0x155
    pairs = (used - half) & 511
    groups = ((pairs & 0x133) + ((pairs >> 2) & 0x133)) & 511
    total = ((groups + (groups >> 4)) & 511) & 0x10F
    return ((total + (total >> 8)) & 511) & 15


class Dictionary(base.Dictionary):
    def __init__(self):
        super().__init__()
        # Additional fixed circuit constants are charged inside the existing
        # 1 KiB state reservation. No new keys or selection tables are cached.
        for index, constant in enumerate((REPEAT, LOW, HIGH, SLOT_CODE, COMPRESS)):
            self.state[240 + 16*index:256 + 16*index] = constant.to_bytes(16,'little')

    @staticmethod
    def _matching_slots(word, fingerprint):
        assert fingerprint != 0
        slot, present = match_slot(word, fingerprint)
        return [slot] if present else []

    @staticmethod
    def _occupied_count(word):
        return occupancy_count(word)

    def storage(self, n=256000):
        result = super().storage(n)
        result['matching_and_occupancy_fixed_width_kernels_defined'] = True
        result['complete_strict_chain_and_vendor_compliance'] = False
        return result
