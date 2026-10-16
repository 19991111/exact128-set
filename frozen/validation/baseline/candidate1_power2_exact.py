"""Exact-overflow profile for the conservative Huawei working contract.

This module only decodes the existing dictionary/RTL outcomes. Hashing,
placement, storage, and memory commands remain in the frozen circuit model.
The contract is a research interpretation of the supplied screenshots.
"""

from dataclasses import dataclass

import candidate1_power2_circuit as circuit
from candidate1_power2 import *


RTL_STATUS = {
    'main': 2,
    'duplicate': 3,
    'overflow_zero_fingerprint': 4,
    'overflow_signature': 5,
    'overflow_capacity': 6,
    'rejected_zero_fingerprint': 7,
    'rejected_signature': 8,
    'rejected_capacity': 9,
}


@dataclass(frozen=True, slots=True)
class InsertResult:
    success: bool
    duplicate: bool
    conflict: bool
    outcome: str
    rtl_status: int
    access: Access


class Dictionary(circuit.Dictionary):
    """Keep conflict accounting separate from successful insertion.

    Overflow is allocated and charged. A key written to it is accepted.
    Exhausting it returns failure and preserves all previously stored keys.
    No additional persistent model state is allocated by this wrapper.
    """

    @property
    def conflict_count(self):
        return self.overflow_count + self.rejected_count

    def insert(self, key):
        outcome, access = super().insert(key)
        status = RTL_STATUS[outcome]
        # The hardware already emits these bounded response codes. These
        # predicates decode them; no new insertion path or RNG is introduced.
        return InsertResult(
            success=2 <= status <= 6,
            duplicate=status == 3,
            conflict=4 <= status <= 9,
            outcome=outcome,
            rtl_status=status,
            access=access,
        )

    def storage(self, n=256000):
        report = super().storage(n)
        report.update(
            profile='power2_exact_v1',
            exact_overflow_capacity=512,
            conflict_events_remain_charged_when_stored_in_overflow=True,
            all_distinct_input_keys_stored_if_conflicts_at_most_512=True,
            official_contract_confirmed=False,
        )
        return report
