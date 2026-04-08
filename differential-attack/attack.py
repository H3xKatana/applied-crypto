import numpy as np
from collections import Counter
from toy_cipher import ToyCipher
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
    if isinstance(cipher, ToyCipher):
        delta = 0x80
    else:
        delta = 0x40

    pairs = generate_differential_pairs(cipher, num_pairs=num_pairs, delta=delta)

    if isinstance(cipher, ToyCipher):
        return _attack_toy_cipher(cipher, pairs, delta)
    else:
        return _attack_sdes(cipher, pairs, delta)


def _attack_toy_cipher(cipher, pairs, delta):
    """Attack toy cipher using differential cryptanalysis."""

    best_key = None
    best_count = 0

    for key in range(1024):
        test_cipher = ToyCipher(key)
        count = 0
        for p, p_prime, c, c_prime in pairs:
            if test_cipher.encrypt(p) == c:
                count += 1

        if count > best_count:
            best_count = count
            best_key = key
            if count == len(pairs):
                return best_key

    return best_key


def _attack_sdes(cipher, pairs, delta):
    """Attack simplified DES."""
    best_key = None
    best_count = 0

    for key in range(1024):
        test_cipher = SimplifiedDES(key << 6)
        count = 0
        for p, p_prime, c, c_prime in pairs:
            if test_cipher.encrypt(p) == c:
                count += 1

        if count > best_count:
            best_count = count
            best_key = key << 6
            if count >= len(pairs) * 0.9:
                break

    return best_key


def measure_attack_effectiveness(cipher_class, key, num_trials=10, pair_counts=None):
    """
    Measure how many pairs needed for successful attack.

    Args:
        cipher_class: Cipher class (ToyCipher or SimplifiedDES)
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
    cipher = ToyCipher(test_key)

    print(f"Testing attack with key: 0x{test_key:03X}")

    for num_pairs in [10, 20, 50, 100]:
        recovered = differential_attack(cipher, num_pairs)
        cipher_correct = ToyCipher(recovered)
        cipher_test = ToyCipher(test_key)

        valid = True
        for _ in range(10):
            p = np.random.randint(0, 256)
            if cipher_correct.encrypt(p) != cipher_test.encrypt(p):
                valid = False
                break

        status = "✓" if valid else "✗"
        print(f"  {num_pairs} pairs: recovered 0x{recovered:03X} {status}")
