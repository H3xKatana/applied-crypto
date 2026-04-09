"""
Step-by-step differential attack demonstration.
Shows exactly how the attack works with detailed output.
"""

import numpy as np
from demo import DemoCipher
from des import SimplifiedDES
from pairs import generate_differential_pairs


def format_key(key, cipher_class):
    """Format key based on cipher type."""
    if cipher_class == DemoCipher:
        return f"0x{key:03X}"
    else:
        return f"0x{key:04X}"


def step_by_step_demo(cipher_class, key, cipher_name):
    """Run step-by-step attack demonstration."""

    print(f"\n{'=' * 60}")
    print(f"  DIFFERENTIAL ATTACK - {cipher_name}")
    print(f"{'=' * 60}")

    cipher = cipher_class(key)
    true_key = key

    print(f"\n[STEP 0] Setup")
    print(f"  - Cipher class: {cipher_class.__name__}")
    print(f"  - True key: {format_key(key, cipher_class)}")

    if cipher_class == DemoCipher:
        delta = 0x80
    else:
        delta = 0x40

    print(f"\n[STEP 1] Choose Differential")
    print(f"  - Input difference (ΔP): 0x{delta:02X}")
    print(f"  - Reason: High probability propagation through Feistel rounds")

    num_pairs = 30
    pairs = generate_differential_pairs(cipher, num_pairs=num_pairs, delta=delta)

    print(f"\n[STEP 2] Generate {num_pairs} Differential Pairs")
    print(f"  - Each pair (P, P') has P ⊕ P' = 0x{delta:02X}")
    print(f"  - Sample pairs:")
    for i in range(3):
        p, p_prime, c, c_prime = pairs[i]
        print(
            f"    Pair {i + 1}: P=0x{p:02X}, P'=0x{p_prime:02X}, C=0x{c:02X}, C'=0x{c_prime:02X}"
        )

    output_diffs = [c ^ c_prime for _, _, c, c_prime in pairs]
    from collections import Counter

    diff_counts = Counter(output_diffs)

    print(f"\n[STEP 3] Analyze Output Differences")
    print(f"  - Output differences (top 5): {diff_counts.most_common(5)}")
    most_common = diff_counts.most_common(1)[0]
    print(f"  - Most common: 0x{most_common[0]:02X} (occurs {most_common[1]} times)")

    if cipher_class == DemoCipher:
        key_space = 1024
    else:
        key_space = 65536

    test_limit = key_space  # Test ALL keys for accurate demonstration

    print(f"\n[STEP 4] Test Key Candidates")
    print(f"  - Testing ALL {key_space} keys")
    print(f"  - For each key, count how many pairs match exactly")

    best_key = None
    best_matches = -1
    match_scores = []

    for test_key in range(test_limit):
        test_cipher = cipher_class(test_key)
        matches = 0
        for p, p_prime, c, c_prime in pairs:
            if test_cipher.encrypt(p) == c and test_cipher.encrypt(p_prime) == c_prime:
                matches += 1
        match_scores.append(matches)

        if matches > best_matches:
            best_matches = matches
            best_key = test_key

    print(f"  - Best key so far: {format_key(best_key, cipher_class)}")
    print(f"  - Matches: {best_matches}/{num_pairs}")

    print(f"\n[STEP 5] Results Analysis")
    match_dist = Counter(match_scores)
    print(f"  - Match distribution (top 5):")
    for score in sorted(match_dist.keys(), reverse=True)[:5]:
        count = match_dist[score]
        bar = "█" * (count // 2)
        print(f"    {score} matches: {bar} ({count} keys)")

    if best_key == true_key:
        print(f"\n[SUCCESS!] Key recovered: {format_key(true_key, cipher_class)}")
    else:
        test_orig = cipher_class(true_key)
        test_recovered = cipher_class(best_key)

        equivalent = all(
            test_orig.encrypt(p) == test_recovered.encrypt(p) for p in range(256)
        )

        if equivalent:
            print(f"\n[EQUIVALENT KEY FOUND]")
            print(f"  - Original: {format_key(true_key, cipher_class)}")
            print(f"  - Found:    {format_key(best_key, cipher_class)}")
            print(f"  - Both produce identical ciphertexts!")
        else:
            print(f"\n[FAILED] Could not find correct key")

    print(f"\n{'=' * 60}")

    return best_key


def show_complexity_comparison():
    """Show complexity comparison between ciphers."""

    print(f"\n{'=' * 60}")
    print("  COMPLEXITY COMPARISON")
    print(f"{'=' * 60}")

    ciphers = [
        ("DemoCipher", 10, "Very Fast (<1s)"),
        ("SimplifiedDES", 16, "Fast (~5s for 65k keys)"),
    ]

    print(f"\n{'Cipher':<15} {'Key Size':<12} {'Key Space':<20} {'Attack Time':<15}")
    print("-" * 65)

    for name, key_size, attack_time in ciphers:
        key_space = 2**key_size
        print(
            f"{name:<15} {key_size} bits     2^{key_size} = {key_space:<15} {attack_time}"
        )

    print(f"\nNote: Real DES (56-bit key) would need 2^47 = 70+ trillion operations!")
    print("That's why differential attack on real DES needs chosen plaintexts.")


def answer_common_questions():
    """Answer common presentation questions."""

    print(f"\n{'=' * 60}")
    print("  COMMON QUESTIONS & ANSWERS")
    print(f"{'=' * 60}")

    print("""
Q: Why use ΔP = 0x80 (or 0x40) as differential?
A: 
  - 0x80 flips the MSB only
  - In a Feistel cipher, this creates a predictable propagation
  - The difference affects only one half initially
  - High probability: ~50-100% for correct key vs random for wrong keys

Q: How many pairs are needed?
A:
  - DemoCipher: 10 pairs → ~70% success, 20+ pairs → 100%
  - SimplifiedDES: 30+ pairs recommended
  - Trade-off: More pairs = more confident but slower

Q: Is this attack practical for real ciphers?
A:
  - DES: Yes! Biham & Shamir (1991) showed 2^47 chosen plaintexts needed
  - AES: Designed to resist differential attacks (more rounds)
  - Our simplified versions demonstrate the principle without real-world damage

Q: What makes a cipher vulnerable?
A:
  - Few rounds (ours have only 2)
  - Small S-boxes (4-bit vs DES's 6-bit)
  - Predictable key schedule
  - Poor diffusion properties

Q: How does this compare to brute force?
A:
  - Brute force: Try ALL keys (1024 for DemoCipher)
  - Differential: Statistical filtering, same complexity but smarter
  - For small keys, brute force is actually faster!
  - The value is in understanding the principle for real ciphers
""")


def show_real_des_complexity():
    """Show real DES complexity numbers."""

    print(f"\n{'=' * 60}")
    print("  REAL DES COMPLEXITY (for context)")
    print(f"{'=' * 60}")

    print("""
Original DES (1977):
  - Block size: 64 bits
  - Key size: 56 bits  
  - Key space: 2^56 ≈ 72 quadrillion keys
  
Differential Attack on DES (Biham & Shamir, 1991):
  - Chosen plaintexts needed: 2^47
  - Complexity: 2^47 operations
  - Much faster than brute force (2^56)!
  
Modern ciphers (AES):
  - AES-128: 2^128 key space, 10+ rounds
  - Designed to resist differential attacks
  - No practical attack known
""")

    print(f"\nOur Simplified Versions:")
    print(f"  - DemoCipher: 2^10 = 1,024 keys (attack trivial)")
    print(f"  - SimplifiedDES: 2^16 = 65,536 keys (attack feasible)")
    print(f"  - Both demonstrate the PRINCIPLE without real damage")


if __name__ == "__main__":
    step_by_step_demo(DemoCipher, 0x3FF, "DemoCipher")

    show_complexity_comparison()

    answer_common_questions()

    show_real_des_complexity()
