#!/usr/bin/env python3
"""
DIFFERENTIAL CRYPTANALYSIS ATTACK - Educational Demonstration

This script demonstrates the differential cryptanalysis attack step-by-step,
showing exactly how the attack works and why it succeeds.

Usage:
    python3 showcase.py [mode] [key] [message]

Examples:
    python3 showcase.py demo 0xFFFFF "Hello"
    python3 showcase.py des 0xCAFE "Secret"
    python3 showcase.py all
"""

import sys
import time
from collections import Counter
from demo import DemoCipher
from des import SimplifiedDES
from pairs import generate_differential_pairs


# Color codes for terminal output
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def print_header(text):
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}  {text}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 70}{Colors.ENDC}\n")


def print_section(text):
    print(f"\n{Colors.BLUE}{Colors.BOLD}[ {text} ]{Colors.ENDC}")


def print_step(step_num, text):
    print(f"{Colors.CYAN}┌─ Step {step_num}: {text}{Colors.ENDC}")
    print(f"{Colors.CYAN}│{Colors.ENDC}")


def print_info(label, value):
    print(f"{Colors.CYAN}│   {label}: {value}{Colors.ENDC}")


def print_success(text):
    print(f"{Colors.GREEN}└─ ✓ {text}{Colors.ENDC}\n")


def print_warning(text):
    print(f"{Colors.YELLOW}└─ ⚠ {text}{Colors.ENDC}\n")


def format_key(key, bits):
    """Format key based on bit size."""
    if bits <= 10:
        return f"0x{key:03X}"
    elif bits <= 16:
        return f"0x{key:04X}"
    elif bits <= 20:
        return f"0x{key:05X}"
    else:
        return f"0x{key:06X}"


def print_progress_bar(current, total, prefix="", suffix=""):
    """Print a progress bar."""
    bar_length = 40
    percent = current / total
    filled = int(bar_length * percent)
    bar = "█" * filled + "░" * (bar_length - filled)
    print(f"\r{prefix} [{bar}] {suffix}", end="", flush=True)
    if current == total:
        print()


def text_to_bytes(text):
    """Convert text to list of byte values."""
    return [ord(c) for c in text]


def bytes_to_hex(byte_list):
    """Convert list of bytes to hex string."""
    return " ".join(f"{b:02X}" for b in byte_list)


def encrypt_message(cipher, message):
    """Encrypt a message and return ciphertext bytes."""
    plaintext_bytes = text_to_bytes(message)
    ciphertext_bytes = [cipher.encrypt(b) for b in plaintext_bytes]
    return plaintext_bytes, ciphertext_bytes


def decrypt_message(cipher, ciphertext_bytes):
    """Decrypt ciphertext bytes back to text."""
    plaintext_bytes = [cipher.decrypt(b) for b in ciphertext_bytes]
    return "".join(chr(b) if 32 <= b < 127 else "?" for b in plaintext_bytes)


def message_demo(cipher_class, key, message, name, key_bits):
    """Demonstrate encryption and decryption of a real message."""

    print_header(f"MESSAGE ENCRYPTION DEMO - {name}")

    cipher = cipher_class(key)

    print_step(0, "SETUP")
    print_info("Cipher", cipher_class.__name__)
    print_info("Key", format_key(key, key_bits))
    print_info("Message", f'"{message}"')

    # Step 1: Show plaintext
    print_step(1, "PLAINTEXT REPRESENTATION")
    plaintext_bytes = text_to_bytes(message)
    print_info("Message Length", f"{len(message)} characters")
    print_info("Plaintext Bytes (ASCII)", bytes_to_hex(plaintext_bytes))

    # Show ASCII values
    print(f"\n{Colors.CYAN}│   Character breakdown:{Colors.ENDC}")
    for i, (char, byte) in enumerate(zip(message[:10], plaintext_bytes[:10])):
        print(f"{Colors.CYAN}│      '{char}' → 0x{byte:02X} ({byte}){Colors.ENDC}")
    if len(message) > 10:
        print(f"{Colors.CYAN}│      ... ({len(message) - 10} more){Colors.ENDC}")

    # Step 2: Encrypt
    print_step(2, "ENCRYPTION")
    _, ciphertext_bytes = encrypt_message(cipher, message)
    print_info("Ciphertext Bytes", bytes_to_hex(ciphertext_bytes))

    # Step 3: Show difference
    print_step(3, "ENCRYPTION RESULT")
    print(f"\n{Colors.CYAN}│   Before encryption:{Colors.ENDC}")
    print(f"{Colors.CYAN}│   {message}{Colors.ENDC}")
    print(f"\n{Colors.CYAN}│   After encryption (hex):{Colors.ENDC}")
    print(f"{Colors.CYAN}│   {bytes_to_hex(ciphertext_bytes)}{Colors.ENDC}")

    # Step 4: Decrypt with same key
    print_step(4, "DECRYPTION (same key)")
    decrypted = decrypt_message(cipher, ciphertext_bytes)
    print_info("Decrypted Message", f'"{decrypted}"')

    if decrypted == message:
        print_success(f"Message decrypted successfully!")
    else:
        print_warning(f"Decryption mismatch!")

    # Step 5: Try wrong key
    print_step(5, "DECRYPTION (wrong key)")
    wrong_key = (key + 1) % (2**key_bits)
    wrong_cipher = cipher_class(wrong_key)
    decrypted_wrong = decrypt_message(wrong_cipher, ciphertext_bytes)
    print_info("Wrong Key", format_key(wrong_key, key_bits))
    print_info("Decrypted Message", f'"{decrypted_wrong}"')
    print_warning(f"Wrong key produces garbage!")

    print()


def attack_demo(cipher_class, key, name, key_bits):
    """Run complete attack demonstration."""

    print_header(f"DIFFERENTIAL ATTACK ON {name}")

    # Step 0: Setup
    print_step(0, "ATTACK SETUP")
    cipher = cipher_class(key)
    true_key = key

    print_info("Target Cipher", cipher_class.__name__)
    print_info("True Key", format_key(key, key_bits))
    print_info("Key Space", f"2^{key_bits} = {2**key_bits} keys")

    # Choose differential
    delta = 0x80  # Works for all Feistel ciphers

    print_info("Chosen Differential (ΔP)", f"0x{delta:02X}")

    # Step 1: Generate pairs
    print_step(1, "GENERATE DIFFERENTIAL PAIRS")
    num_pairs = 30

    print_info("Number of Pairs", str(num_pairs))
    print_info("Difference", f"P ⊕ P' = 0x{delta:02X}")

    pairs = generate_differential_pairs(cipher, num_pairs=num_pairs, delta=delta)

    print(f"{Colors.CYAN}│{Colors.ENDC}")
    print(f"{Colors.CYAN}│   Sample pairs (first 5):{Colors.ENDC}")
    for i in range(min(5, len(pairs))):
        p, p_prime, c, c_prime = pairs[i]
        print(
            f"{Colors.CYAN}│      {i + 1}. P=0x{p:02X} → P'=0x{p_prime:02X}  │  C=0x{c:02X} → C'=0x{c_prime:02X}{Colors.ENDC}"
        )

    # Step 2: Analyze output differences
    print_step(2, "ANALYZE OUTPUT DIFFERENCES")

    output_diffs = [c ^ c_prime for _, _, c, c_prime in pairs]
    diff_counts = Counter(output_diffs)

    print_info("Total Unique Differences", str(len(diff_counts)))
    print_info(
        "Most Common",
        f"0x{diff_counts.most_common(1)[0][0]:02X} ({diff_counts.most_common(1)[0][1]} times)",
    )

    print(f"\n{Colors.CYAN}│   Distribution (top 5):{Colors.ENDC}")
    for diff, count in diff_counts.most_common(5):
        bar = "▓" * count + "░" * (num_pairs - count)
        print(f"{Colors.CYAN}│      ΔC=0x{diff:02X}: [{bar[:20]}] {count}{Colors.ENDC}")

    # Step 3: Key search
    key_space = 2**key_bits

    print_step(3, "KEY RECOVERY ATTACK")
    print_info("Testing Keys", f"0 to {key_space - 1}")
    print_info("Strategy", "Count matching pairs per key")

    best_key = None
    best_matches = -1

    # Progress bar for key testing
    print(f"\n{Colors.CYAN}│   Progress:{Colors.ENDC}")
    for i, test_key in enumerate(range(key_space)):
        test_cipher = cipher_class(test_key)
        matches = 0
        for p, p_prime, c, c_prime in pairs:
            if test_cipher.encrypt(p) == c and test_cipher.encrypt(p_prime) == c_prime:
                matches += 1

        if matches > best_matches:
            best_matches = matches
            best_key = test_key

        # Show progress every 10%
        if key_space > 100 and i % (key_space // 10) == 0:
            print_progress_bar(
                i + 1, key_space, f"{Colors.CYAN}│   ", f"{i + 1}/{key_space} keys"
            )

    print_progress_bar(key_space, key_space, f"{Colors.CYAN}│   ", f"Complete!")

    # Step 4: Results
    print_step(4, "RESULTS")

    print_info("Best Key Found", format_key(best_key, key_bits))
    print_info("Matching Pairs", f"{best_matches}/{num_pairs}")

    # Analyze match distribution
    test_cipher = cipher_class(best_key)

    if best_key == true_key:
        print_success(f"Key recovered: {format_key(true_key, key_bits)}")
    else:
        # Check equivalence
        test_orig = cipher_class(true_key)
        equivalent = all(
            test_orig.encrypt(p) == test_cipher.encrypt(p) for p in range(256)
        )

        if equivalent:
            print_warning(f"Equivalent key found!")
            print(
                f"{Colors.CYAN}│   Original key: {format_key(true_key, key_bits)}{Colors.ENDC}"
            )
            print(
                f"{Colors.CYAN}│   Found key:    {format_key(best_key, key_bits)}{Colors.ENDC}"
            )
            print(f"{Colors.CYAN}│   Both produce identical ciphertexts!{Colors.ENDC}")
        else:
            print_warning(f"Could not find exact key")


def explain_differential(cipher_class):
    """Explain why certain differentials work."""

    print_section("WHY DIFFERENTIAL ATTACK WORKS")

    print("""
┌────────────────────────────────────────────────────────────────────────┐
│                     FEISTEL CIPHER STRUCTURE                          │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   Plaintext (8 bits)  ──►  [L0|R0]                                    │
│                              │                                          │
│                              ▼                                          │
│                     ┌──────► f(R0, K1) ──► XOR with L0                │
│                     │       │                                          │
│                     │       ▼                                          │
│                     │    [L1|R1]                                       │
│                     │       │                                          │
│                     ▼       │                                          │
│                     ┌──────► f(R1, K2) ──► XOR with L1                │
│                     │       │                                          │
│                     │       ▼                                          │
│                     │    [L2|R2] = Ciphertext                         │
│                     │                                                  │
└────────────────────────────────────────────────────────────────────────┘

KEY INSIGHT:
  With input difference ΔP = 0x80, we have:
  
  - ΔL0 = 0x08 (left half differs by 8)
  - ΔR0 = 0x00 (right half SAME!)
  
  Since ΔR0 = 0, the f-function in round 1 sees SAME input!
  The output difference depends only on the key XOR behavior.
  
  This creates a HIGH PROBABILITY characteristic:
  - Correct key: predictable output difference
  - Wrong keys: random output difference
""")


def show_theory():
    """Show theoretical background."""

    print_header("DIFFERENTIAL CRYPTANALYSIS THEORY")

    print("""
┌────────────────────────────────────────────────────────────────────────┐
│                          CORE CONCEPT                                 │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  DIFFERENTIAL = pair of plaintexts with known XOR difference           │
│                                                                        │
│    ΔP = P ⊕ P'    (known by attacker)                                  │
│                                                                        │
│  The attacker's goal: find which keys produce EXPECTED output diff     │
│                                                                        │
├────────────────────────────────────────────────────────────────────────┤
│                        ATTACK ALGORITHM                               │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  1. Choose a "good" differential (high probability path)              │
│  2. Generate many plaintext pairs with this difference                │
│  3. For each candidate key:                                           │
│     a. Encrypt both plaintexts                                        │
│     b. Check if output difference matches expected                    │
│     c. Count how many pairs "work"                                    │
│  4. Key with most matching pairs is likely correct                   │
│                                                                        │
├────────────────────────────────────────────────────────────────────────┤
│                      WHY IT WORKS                                      │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  For CORRECT key:                                                      │
│    - The differential follows a predictable path                      │
│    - Output difference is CORRELATED with input difference            │
│    - Many pairs produce expected output                               │
│                                                                        │
│  For WRONG keys:                                                       │
│    - The differential behavior is random                               │
│    - Output difference is UNCORRELATED                                │
│    - Few or no pairs match expected output                            │
│                                                                        │
│  STATISTICAL ADVANTAGE: By testing many pairs, the correct key        │
│  stands out from the noise.                                           │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
""")


def show_complexity():
    """Show complexity comparison."""

    print_header("ATTACK COMPLEXITY COMPARISON")

    print(f"""
{Colors.BOLD}Cipher Comparison:{Colors.ENDC}

┌─────────────────────┬───────────┬────────────────────┬──────────────────┐
│ Cipher              │ Key Size  │ Key Space          │ Attack Time      │
├─────────────────────┼───────────┼────────────────────┼──────────────────┤
│ DemoCipher          │ 20 bits   │ 2^20 = 1,048,576   │ ~30 seconds      │
│ SimplifiedDES       │ 16 bits   │ 2^16 = 65,536      │ ~5 seconds       │
│ Real DES            │ 56 bits   │ 2^56 = 7.2×10^16   │ 2^47 operations  │
│ AES-128             │ 128 bits  │ 2^128              │ Not feasible     │
└─────────────────────┴───────────┴────────────────────┴──────────────────┘

{Colors.YELLOW}Note on Real DES:{Colors.ENDC}
  - Differential attack (Biham & Shamir, 1991) needs 2^47 chosen plaintexts
  - This is 512x FASTER than brute force (2^56)
  - Modern ciphers (AES) have more rounds and resist this attack
""")


def show_faq():
    """Show frequently asked questions."""

    print_header("FREQUENTLY ASKED QUESTIONS")

    faqs = [
        (
            "Why ΔP = 0x80 (or 0x40)?",
            """Flips only one bit - creates predictable propagation in Feistel.
            The difference affects only one half initially, making the
            differential path high-probability.""",
        ),
        (
            "How many pairs needed?",
            """DemoCipher (20-bit): 50+ pairs recommended
            SimplifiedDES (16-bit): 30+ pairs recommended.
            More pairs = more confident but slower.""",
        ),
        (
            "Is this practical on real ciphers?",
            """DES: Yes! Biham & Shamir (1991) showed 2^47 plaintexts needed.
            AES: Designed to resist - more rounds, better diffusion.
            Our versions demonstrate the principle safely.""",
        ),
        (
            "Why multiple keys can work?",
            """S-boxes in our simplified cipher are not perfectly bijective.
            Different keys can produce identical encryption functions.
            This is a weakness in the simplified design.""",
        ),
        (
            "Difference from brute force?",
            """Same complexity (test all keys), but smarter.
Uses statistics to filter - correct key stands out.
For small keys, brute force is actually faster!
Value is in understanding the principle.""",
        ),
    ]

    for i, (question, answer) in enumerate(faqs, 1):
        print(f"{Colors.BOLD}Q{i}: {question}{Colors.ENDC}")
        print(f"{answer}\n")


def main():
    """Main entry point."""

    print(f"""
{Colors.HEADER}
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        DIFFERENTIAL CRYPTANALYSIS ATTACK DEMONSTRATION              ║
║                                                                      ║
║        Educational Implementation for Applied Crypto TP             ║
║                                                                      ║
╚════════════════════════════════════════════════════════════════════╝
{Colors.ENDC}
    """)

    # Show theory first
    show_theory()

    # Parse arguments
    if len(sys.argv) < 2 or sys.argv[1] == "all":
        # Run full demo
        # Message demo first
        message_demo(DemoCipher, 0xFFFFF, "Crypto", "DEMO CIPHER", 20)
        time.sleep(1)
        # Then attack
        attack_demo(DemoCipher, 0xFFFFF, "DEMO CIPHER (20-bit key, 4 rounds)", 20)
        time.sleep(1)
        show_complexity()
        show_faq()
    elif sys.argv[1] == "demo":
        key = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xFFFFF
        message = sys.argv[3] if len(sys.argv) > 3 else "Hello"
        message_demo(DemoCipher, key, message, "DEMO CIPHER", 20)
        time.sleep(1)
        attack_demo(DemoCipher, key, "DEMO CIPHER", 20)
    elif sys.argv[1] == "des":
        key = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xCAFE
        message = sys.argv[3] if len(sys.argv) > 3 else "Secret"
        explain_differential(SimplifiedDES)
        message_demo(SimplifiedDES, key, message, "SIMPLIFIED DES", 16)
        time.sleep(1)
        attack_demo(SimplifiedDES, key, "SIMPLIFIED DES (16-bit key)", 16)
    else:
        print(f"Usage: python3 showcase.py [demo|des|all] [key] [message]")
        print(f"Examples:")
        print(f'  python3 showcase.py demo 0xFFFFF "Hello"')
        print(f'  python3 showcase.py des 0xCAFE "Secret"')
        print(f"  python3 showcase.py all")


if __name__ == "__main__":
    main()
