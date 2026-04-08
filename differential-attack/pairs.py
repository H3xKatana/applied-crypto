import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from toy_cipher import ToyCipher
from des import SimplifiedDES


def generate_differential_pairs(cipher, num_pairs=100, delta=None):
    """
    Generate plaintext pairs with controlled XOR difference.

    Args:
        cipher: Cipher instance (ToyCipher or SimplifiedDES)
        num_pairs: Number of pairs to generate
        delta: XOR difference between plaintexts (default: 0x80 for toy, 0x40 for DES)

    Returns:
        List of tuples: (plaintext, plaintext_prime, ciphertext, ciphertext_prime)
    """
    if delta is None:
        if isinstance(cipher, ToyCipher):
            delta = 0x80
        elif isinstance(cipher, SimplifiedDES):
            delta = 0x40
        else:
            delta = 0x01

    pairs = []
    for _ in range(num_pairs):
        p = np.random.randint(0, 256)
        p_prime = p ^ delta
        c = cipher.encrypt(p)
        c_prime = cipher.encrypt(p_prime)
        pairs.append((p, p_prime, c, c_prime))

    return pairs


def find_good_differential(cipher, max_pairs=500):
    """Find high-probability differential by analyzing output XOR distribution."""
    from collections import Counter

    test_deltas = [0x01, 0x02, 0x40, 0x80, 0xC0, 0xFF]
    best_result = (None, 0, {})

    for delta in test_deltas:
        output_diffs = Counter()
        for _ in range(max_pairs):
            p = np.random.randint(0, 256)
            p_prime = p ^ delta
            c = cipher.encrypt(p)
            c_prime = cipher.encrypt(p_prime)
            output_diffs[c ^ c_prime] += 1

        most_common_output, count = output_diffs.most_common(1)[0]
        prob = count / max_pairs

        if prob > best_result[1]:
            best_result = (delta, prob, dict(output_diffs))

    return best_result[0], best_result[1], best_result[2]


if __name__ == "__main__":
    # Test with toy cipher
    cipher = ToyCipher(key=0x3FF)  # 10-bit key
    pairs = generate_differential_pairs(cipher, num_pairs=10)
    print(f"Generated {len(pairs)} differential pairs for ToyCipher")

    delta, prob, _ = find_good_differential(cipher)
    print(f"Best differential: 0x{delta:02X} (probability: {prob:.2%})")
