"""Explicit fixed-width integer circuits for the power-of-two dictionary.

These circuits expand matching and selection rather than counting them as a
single operation. They are combinational DAGs; only the separately defined
hash/address chains satisfy the literal immediate-predecessor chain rule.
"""

from dataclasses import dataclass
import candidate1_power2 as model


W = 14
LANES = 9
REPEAT = sum(1 << (W * j) for j in range(LANES))
LOW = sum(((1 << (W - 1)) - 1) << (W * j) for j in range(LANES))
HIGH = sum(1 << (W * j + W - 1) for j in range(LANES))
SLOT_CODE = sum(j << (125 - (W * j + W - 1)) for j in range(LANES))
COMPRESS = sum(1 << (117 - (W * j + W - 1) + j) for j in range(LANES))


@dataclass(frozen=True)
class Wire:
    name: str


class Circuit:
    """Trace verifier, not persistent storage of the online algorithm."""
    def __init__(self, inputs):
        self.values = dict(inputs)
        self.nodes = []
        self.depth = {name: 0 for name in inputs}

    def op(self, operation, width, left, right):
        assert operation in ('add', 'subtract', 'shift_left', 'shift_right',
                             'and', 'or', 'xor', 'multiply_constant')
        if operation == 'multiply_constant':
            assert isinstance(right, int)
        a = self.values[left.name] if isinstance(left, Wire) else left
        b = self.values[right.name] if isinstance(right, Wire) else right
        if operation == 'add':
            value = a + b
        elif operation == 'subtract':
            value = a - b
        elif operation == 'shift_left':
            value = a << b
        elif operation == 'shift_right':
            value = a >> b
        elif operation == 'and':
            value = a & b
        elif operation == 'or':
            value = a | b
        elif operation == 'xor':
            value = a ^ b
        else:
            value = a * b
        value &= (1 << width) - 1
        name = f'n{len(self.nodes) + 1}'
        inputs = [x.name for x in (left, right) if isinstance(x, Wire)]
        self.depth[name] = 1 + max((self.depth[x] for x in inputs), default=0)
        self.nodes.append({'name': name, 'operation': operation, 'width_bits': width,
                           'left': left.name if isinstance(left, Wire) else hex(left),
                           'right': right.name if isinstance(right, Wire) else hex(right),
                           'depth': self.depth[name]})
        self.values[name] = value
        return Wire(name)

    def get(self, wire):
        return self.values[wire.name]

    def describe(self):
        indices = {n['name']: i for i, n in enumerate(self.nodes)}
        older_edges = []
        for index, node in enumerate(self.nodes):
            for side in ('left', 'right'):
                name = node[side]
                if name in indices and indices[name] != index - 1:
                    older_edges.append({'producer': name, 'consumer': node['name']})
        return {'primitive_count': len(self.nodes),
                'dependency_depth': max(self.depth.values()),
                'maximum_word_bits': max((n['width_bits'] for n in self.nodes), default=0),
                'literal_single_chain': not older_edges,
                'nonadjacent_dependency_edges': older_edges,
                'nodes': self.nodes}


def zero_lanes(c, word):
    # Each 14-bit lane's low 13 bits plus 8191 fit in 14 bits. No addition
    # carries across lanes. The high bit becomes 1 iff any lane bit was 1.
    low = c.op('and', 128, word, LOW)
    added = c.op('add', 128, low, LOW)
    combined = c.op('or', 128, added, word)
    inverted = c.op('xor', 128, combined, (1 << 128) - 1)
    return c.op('and', 128, inverted, HIGH)


def present(c, mask):
    # This mask has no bits above 125, so positive mask-1 never sets bit 127.
    decreased = c.op('subtract', 128, mask, 1)
    sign = c.op('shift_right', 1, decreased, 127)
    return c.op('xor', 1, sign, 1)


def matching(c, word, fingerprint):
    broadcast = c.op('multiply_constant', 128, fingerprint, REPEAT)
    differences = c.op('xor', 128, word, broadcast)
    mask = zero_lanes(c, differences)
    # This decoder requires <=1 set lane bit. The dictionary invariant gives
    # that condition for nonzero query tags, across both candidate buckets.
    weighted = c.op('multiply_constant', 256, mask, SLOT_CODE)
    shifted = c.op('shift_right', 256, weighted, 125)
    slot = c.op('and', 4, shifted, 15)
    return mask, slot, present(c, mask)


def occupancy(c, word):
    free = zero_lanes(c, word)
    compressed = c.op('multiply_constant', 128, free, COMPRESS)
    shifted = c.op('shift_right', 128, compressed, 117)
    packed_free = c.op('and', 9, shifted, 511)
    used = c.op('xor', 9, packed_free, 511)
    half = c.op('shift_right', 9, used, 1)
    half = c.op('and', 9, half, 0x155)
    pairs = c.op('subtract', 9, used, half)
    lower = c.op('and', 9, pairs, 0x133)
    upper = c.op('shift_right', 9, pairs, 2)
    upper = c.op('and', 9, upper, 0x133)
    groups = c.op('add', 9, lower, upper)
    upper = c.op('shift_right', 9, groups, 4)
    total = c.op('add', 9, groups, upper)
    total = c.op('and', 9, total, 0x10F)
    upper = c.op('shift_right', 9, total, 8)
    total = c.op('add', 9, total, upper)
    return c.op('and', 4, total, 15), free


def update(c, word, count, fingerprint):
    shift = c.op('multiply_constant', 8, count, 14)
    inserted = c.op('shift_left', 128, fingerprint, shift)
    return c.op('or', 128, word, inserted)


def mux(c, selector, left, right, width):
    mask = c.op('subtract', width, 0, selector)
    difference = c.op('xor', width, left, right)
    selected = c.op('and', width, difference, mask)
    return c.op('xor', width, right, selected)


def left_is_less_or_equal(c, left_count, right_count):
    difference = c.op('subtract', 5, left_count, right_count)
    decreased = c.op('subtract', 5, difference, 1)
    return c.op('shift_right', 1, decreased, 4)


def main_address(c, left, right, left_slot, right_slot, choose_left):
    la = c.op('multiply_constant', 19, left, 9)
    la = c.op('add', 19, la, left_slot)
    ra = c.op('multiply_constant', 19, right, 9)
    ra = c.op('add', 19, ra, model.B * 9)
    ra = c.op('add', 19, ra, right_slot)
    return mux(c, choose_left, la, ra, 19)


def reconstruct(c, record, left, fingerprint):
    high = c.op('shift_left', 128, record, 28)
    tag = c.op('shift_left', 128, fingerprint, 14)
    value = c.op('or', 128, high, tag)
    return c.op('or', 128, value, left)


def equal_full(c, left, right):
    difference = c.op('xor', 128, left, right)
    negative = c.op('subtract', 128, 0, difference)
    any_bit = c.op('or', 128, difference, negative)
    sign = c.op('shift_right', 1, any_bit, 127)
    return c.op('xor', 1, sign, 1)


def cam_search(c, key, count, entries):
    hit = None
    for index, stored in enumerate(entries):
        equality = equal_full(c, key, stored)
        difference = c.op('subtract', 11, count, index + 1)
        sign = c.op('shift_right', 1, difference, 10)
        valid = c.op('xor', 1, sign, 1)
        equality = c.op('and', 1, equality, valid)
        hit = equality if hit is None else c.op('or', 1, hit, equality)
    return hit


def chain(key, stages):
    value = key
    for operation, constant in stages:
        if operation == 'multiply_constant':
            value = value * constant & model.MASK256
        elif operation == 'and_constant':
            value &= constant
        elif operation == 'xor_constant':
            value ^= constant
        else:
            value >>= constant
    return value


def make_example_blocks():
    blocks = {}
    inputs = {'word': 0, 'f': 7, 'count': 0, 'left': 23, 'right': 30,
              'ls': 2, 'rs': 3, 'select': 1, 'record': 17, 'key': 21}
    w = {name: Wire(name) for name in inputs}
    for name, builder in {
        'matching_per_bucket': lambda c: matching(c, w['word'], w['f']),
        'occupancy_per_bucket': lambda c: occupancy(c, w['word']),
        'auxiliary_insert_update': lambda c: update(c, w['word'], w['count'], w['f']),
        'choose_emptier_bucket': lambda c: left_is_less_or_equal(c, w['ls'], w['rs']),
        'one_main_record_address': lambda c: main_address(c, w['left'], w['right'], w['ls'], w['rs'], w['select']),
        'reconstruct_and_full_compare': lambda c: equal_full(c, reconstruct(c, w['record'], w['left'], w['f']), w['key']),
    }.items():
        circuit = Circuit(inputs)
        builder(circuit)
        blocks[name] = circuit.describe()
    inputs = {'key': 21, 'count': 0, **{f'entry{j}': 0 for j in range(512)}}
    circuit = Circuit(inputs)
    cam_search(circuit, Wire('key'), Wire('count'), [Wire(f'entry{j}') for j in range(512)])
    blocks['declared_exact_512_entry_cam'] = circuit.describe()
    return blocks
