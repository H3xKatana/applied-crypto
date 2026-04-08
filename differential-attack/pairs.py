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
        delta: XOR difference between plaintexts (default: 0x80 for toy, 0x4000 for DES)

    Returns:
        List of tuples: (plaintext, plaintext_prime, ciphertext, ciphertext_prime)
    """
    if delta is None:
        if isinstance(cipher, ToyCipher):
            delta = 0x80
        elif isinstance(cipher, SimplifiedDES):
            delta = 0x40  # Good differential for SDES
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


def find_good_differential(cipher, max_pairs=1000):
    """
    Find high-probability differential for a cipher.
    Tests various input differences and returns the best one.

    Args:
        cipher: Cipher instance
        max_pairs: Number of pairs to test per difference

    Returns:
        Best differential and its observed probability
    """
    best_delta = None
    best_count = 0

    # Test common differentials
    test_deltas = [0x01, 0x02, 0x40, 0x80, 0xFF]

    for delta in test_deltas:
        count = 0
        for _ in range(max_pairs):
            p = np.random.randint(0, 256)
            p_prime = p ^ delta
            c = cipher.encrypt(p)
            c_prime = cipher.encrypt(p_prime)

            # Count pairs where output difference is stable
            if c ^ c_prime == delta:
                count += 1

        if count > best_count:
            best_count = count
            best_delta = delta

    return best_delta, best_count / max_pairs


if __name__ == "__main__":
    # Test with toy cipher
    cipher = ToyCipher(key=0x3FF)  # 10-bit key
    pairs = generate_differential_pairs(cipher, num_pairs=10)
    print(f"Generated {len(pairs)} differential pairs for ToyCipher")

    delta, prob = find_good_differential(cipher)
    print(f"Best differential: 0x{delta:02X} (probability: {prob:.2%})")
