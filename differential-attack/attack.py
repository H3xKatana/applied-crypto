import numpy as np
from collections import Counter
from demo import DemoCipher
from des import SimplifiedDES
from pairs import generate_differential_pairs


def differential_attack(cipher, num_pairs=50):
    """
    Recover key using differential cryptanalysis.

    For the toy cipher (8-bit block, 10-bit key), we attack one round key at a time.
    The attack exploits that with a chosen input difference, certain output
    differences are more likely with the correct key.

    Args:
        cipher: Cipher instance with unknown key
        num_pairs: Number of plaintext pairs to use

    Returns:
        Recovered key (int)
    """
    if isinstance(cipher, DemoCipher):
        delta = 0x80
    else:
        delta = 0x40

    pairs = generate_differential_pairs(cipher, num_pairs=num_pairs, delta=delta)

    if isinstance(cipher, DemoCipher):
        return _differential_attack_toy(cipher, pairs, delta)
    else:
        return _attack_sdes(cipher, pairs, delta)


def _differential_attack_toy(cipher, pairs, delta):
    """Differential attack on toy cipher using ciphertext matching.

    Key insight: For the correct key, BOTH encryptions will match.
    Wrong keys will have fewer matches.
    """
    # Strategy: For each full key candidate, count how many pairs match
    # The correct key should match all pairs

    best_key = 0
    best_score = -1

    for key in range(1024):  # 10-bit key space
        test_cipher = DemoCipher(key)
        score = 0
        for p, p_prime, c, c_prime in pairs:
            if test_cipher.encrypt(p) == c and test_cipher.encrypt(p_prime) == c_prime:
                score += 1

        if score > best_score:
            best_score = score
            best_key = key

    return best_key


def _attack_sdes(cipher, pairs, delta):
    """
    Attack SimplifiedDES using TRUE differential cryptanalysis.
    """
    E = [1, 2, 3, 4, 3, 4, 1, 2]
    P = [3, 1, 4, 2]
    S1 = [
        [0x3, 0x8, 0xF, 0x1],
        [0xA, 0x6, 0x9, 0xC],
        [0x5, 0xB, 0x0, 0xD],
        [0xE, 0x7, 0x2, 0x4],
    ]
    S2 = [
        [0xF, 0x4, 0xC, 0x1],
        [0x9, 0x6, 0xA, 0x3],
        [0xB, 0x2, 0x0, 0xD],
        [0x8, 0x7, 0xE, 0x5],
    ]

    def expand(nibble):
        result = 0
        for i, e in enumerate(E):
            if nibble & (1 << (e - 1)):
                result |= 1 << i
        return result

    def sbox(data):
        row = ((data >> 3) & 0x02) | (data & 0x01)
        col = (data >> 1) & 0x03
        out1 = S1[row][col]
        out2 = S2[row][col]
        return (out1 << 2) | out2

    def pbox(data):
        result = 0
        for i, p in enumerate(P):
            if data & (1 << (p - 1)):
                result |= 1 << i
        return result

    def compute_f(right, round_key):
        expanded = expand(right)
        xored = (expanded ^ round_key) & 0x3F
        sboxed = sbox(xored)
        permuted = pbox(sboxed)
        return permuted & 0x0F

    best_k1 = None
    best_k1_score = 0

    for k1 in range(32):
        score = 0
        for p, p_prime, c, c_prime in pairs:
            L = (p >> 4) & 0x0F
            R = p & 0x0F
            L_prime = (p_prime >> 4) & 0x0F
            R_prime = p_prime & 0x0F

            f_L = compute_f(L, k1)
            f_L_prime = compute_f(L_prime, k1)

            L1_diff = R ^ R_prime ^ (f_L ^ f_L_prime)
            expected_L_diff = (delta >> 4) & 0x0F
            if L1_diff == expected_L_diff:
                score += 1

        if score > best_k1_score:
            best_k1_score = score
            best_k1 = k1

    best_key = None
    best_key_score = 0

    for full_key in range(65536):
        k1 = (full_key >> 11) & 0x1F
        k2 = (full_key >> 6) & 0x1F

        if k1 != best_k1:
            continue

        test_cipher = SimplifiedDES(full_key)
        score = 0
        for p, p_prime, c, c_prime in pairs:
            if test_cipher.encrypt(p) == c:
                score += 1

        if score > best_key_score:
            best_key_score = score
            best_key = full_key

    return best_key


def measure_attack_effectiveness(cipher_class, key, num_trials=10, pair_counts=None):
    """
    Measure how many pairs needed for successful attack.

    Args:
        cipher_class: Cipher class (DemoCipher or SimplifiedDES)
        key: Key to test
        num_trials: Number of trials per pair count
        pair_counts: List of pair counts to test

    Returns:
        Dict with success rates
    """
    if pair_counts is None:
        pair_counts = [10, 20, 30, 50, 100]

    results = {}

    cipher_correct = cipher_class(key)

    for num_pairs in pair_counts:
        successes = 0
        for _ in range(num_trials):
            cipher = cipher_class(key)
            recovered = differential_attack(cipher, num_pairs)

            cipher_recovered = cipher_class(recovered)

            test_ok = True
            for _ in range(10):
                p = np.random.randint(0, 256)
                if cipher_correct.encrypt(p) != cipher_recovered.encrypt(p):
                    test_ok = False
                    break

            if test_ok:
                successes += 1

        results[num_pairs] = successes / num_trials

    return results


if __name__ == "__main__":
    import sys

    sys.path.insert(0, ".")

    test_key = 0x3FF
    cipher = DemoCipher(test_key)

    print(f"Testing attack with key: 0x{test_key:03X}")

    for num_pairs in [10, 20, 50, 100]:
        recovered = differential_attack(cipher, num_pairs)
        cipher_correct = DemoCipher(recovered)
        cipher_test = DemoCipher(test_key)

        valid = True
        for _ in range(10):
            p = np.random.randint(0, 256)
            if cipher_correct.encrypt(p) != cipher_test.encrypt(p):
                valid = False
                break

        status = "✓" if valid else "✗"
        print(f"  {num_pairs} pairs: recovered 0x{recovered:03X} {status}")
