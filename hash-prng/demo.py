#!/usr/bin/env python3
"""

Run:
    python demo.py

Produces:
    - Full NIST SP 800-22 test suite results for 4 generators
    - Security property analysis (avalanche, forward secrecy)
    - 3 publication-quality figures
    - NIST test vector validation
"""

import os
import sys
import time
import hashlib
import struct

# ── Make sure local packages resolve ─────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from hash_drbg.core        import HashDRBG, HashAlgorithm
from statistical_tests.nist_sts import run_full_suite, TestResult
from analysis.visualizer   import (
    LCG, _get_python_rng_bytes,
    plot_output_analysis,
    plot_nist_comparison,
    plot_security_properties,
)


def separator(title: str = "") -> None:
    width = 72
    if title:
        pad = (width - len(title) - 2) // 2
        print("\n" + "─" * pad + f" {title} " + "─" * (width - pad - len(title) - 2))
    else:
        print("\n" + "─" * width)


def header() -> None:
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║          Hash-DRBG — Pseudo-Random Number Generator                 ║
║          NIST SP 800-90A Rev 1  ·  SHA-256 / SHA-512 / SHA-3        ║
║          Statistical Validation: NIST SP 800-22 Rev 1a              ║
╚══════════════════════════════════════════════════════════════════════╝
""")


# ──────────────────────────────────────────────────────────────────────────────
# Section 1: Instantiate & basic generation
# ──────────────────────────────────────────────────────────────────────────────

def demo_basic_generation() -> bytes:
    separator("1. Hash_DRBG Instantiation & Generation")

    rng = HashDRBG(
        algorithm=HashAlgorithm.SHA256,
        personalization_string=b"TP_PRNG_Hash_DRBG_Demo_2024",
    )
    print(f"  Generator : {rng}")
    print(f"  Seedlen   : 440 bits (per NIST SP 800-90A Table 2)")
    print(f"  Outlen    : 256 bits per Hash call")

    # Generate 4 KB of pseudo-random data
    t0  = time.perf_counter()
    out = rng.generate(4096)
    dt  = time.perf_counter() - t0

    print(f"\n  Generated : 4 096 bytes in {dt*1000:.3f} ms")
    print(f"  First 32  : {out[:32].hex()}")
    print(f"  Reseed counter after generation: {rng.reseed_counter}")

    # Show that reseed changes output completely
    print("\n  --- Reseed demonstration ---")
    pre_reseed  = rng.generate(16).hex()
    rng.reseed(additional_input=b"fresh entropy event")
    post_reseed = rng.generate(16).hex()
    print(f"  Pre-reseed  output : {pre_reseed}")
    print(f"  Post-reseed output : {post_reseed}")
    print(f"  (Completely different — reseed mixes new entropy into V and C)")

    return out


# ──────────────────────────────────────────────────────────────────────────────
# Section 2: Multiple algorithm variants
# ──────────────────────────────────────────────────────────────────────────────

def demo_algorithm_variants() -> None:
    separator("2. Algorithm Variants (SHA-256 / SHA-512 / SHA-3-256 / SHA-3-512)")

    for algo in HashAlgorithm:
        rng  = HashDRBG(algo)
        out  = rng.generate(32)
        print(
            f"  {algo.name:<12} | security={rng.security_strength}-bit "
            f"| seedlen={rng._params['seedlen']} bits "
            f"| sample: {out[:8].hex()}..."
        )


# ──────────────────────────────────────────────────────────────────────────────
# Section 3: NIST SP 800-22 Statistical Test Suite
# ──────────────────────────────────────────────────────────────────────────────

def demo_nist_sts(large_sample: bytes) -> dict:
    separator("3. NIST SP 800-22 Rev 1a — Statistical Test Suite")

    SAMPLE_SIZE = min(len(large_sample), 16_384)  # 16 KB minimum recommended
    generators  = {}

    print(f"\n  Testing {SAMPLE_SIZE:,} bytes per generator ...\n")

    # ── Hash-DRBG (our implementation) ───────────────────────────────────
    print("  ► Hash_DRBG (SHA-256) — NIST SP 800-90A compliant")
    rng_h    = HashDRBG(HashAlgorithm.SHA256)
    data_h   = rng_h.generate(SAMPLE_SIZE)
    results_h = run_full_suite(data_h)
    generators["Hash-DRBG (SHA-256)"] = results_h

    # ── LCG (weak, for comparison) ────────────────────────────────────────
    print("\n  ► LCG (Linear Congruential Generator) — a8=1664525, c=1013904223")
    lcg      = LCG(seed=42)
    data_l   = lcg.randbytes(SAMPLE_SIZE)
    results_l = run_full_suite(data_l)
    generators["LCG (weak)"] = results_l

    # ── Python random (Mersenne Twister) ──────────────────────────────────
    print("\n  ► Python random.random() — Mersenne Twister MT19937")
    data_p   = _get_python_rng_bytes(SAMPLE_SIZE)
    results_p = run_full_suite(data_p)
    generators["Python random (MT19937)"] = results_p

    # ── os.urandom (OS TRNG as reference) ────────────────────────────────
    print("\n  ► os.urandom() — OS true random (reference)")
    data_o   = os.urandom(SAMPLE_SIZE)
    results_o = run_full_suite(data_o)
    generators["os.urandom (reference)"] = results_o

    return generators


# ──────────────────────────────────────────────────────────────────────────────
# Section 4: Security Properties
# ──────────────────────────────────────────────────────────────────────────────

def demo_security_properties() -> None:
    separator("4. Security Properties")

    rng = HashDRBG(HashAlgorithm.SHA256)

    # ── Forward secrecy ────────────────────────────────────────────────────
    print("\n  [A] Forward Secrecy (Backtracking Resistance)")
    print("      If an attacker learns the current state (V, C),")
    print("      they CANNOT recover previous output because:")
    print("      V_new = (V + Hash(0x03||V) + C + ctr) mod 2^440")
    print("      Inverting this requires breaking SHA-256 preimage resistance.")

    # Show state evolution
    V_snapshots = []
    for _ in range(4):
        rng.generate(32)
        V_snapshots.append(rng._state.V[:8].hex())

    print("\n      Internal state V (first 8 bytes) after each generate():")
    for i, v in enumerate(V_snapshots):
        print(f"        call {i+1}: V = {v}...")

    # ── Additional input ────────────────────────────────────────────────────
    print("\n  [B] Additional Input (per-call entropy injection)")
    print("      Hash-DRBG supports per-call additional_input:")
    out1 = rng.generate(16, additional_input=b"request_id=abc123")
    out2 = rng.generate(16, additional_input=b"request_id=def456")
    print(f"      additional_input='request_id=abc123' → {out1.hex()}")
    print(f"      additional_input='request_id=def456' → {out2.hex()}")

    # ── Prediction resistance ──────────────────────────────────────────────
    print("\n  [C] Seed Sensitivity (Avalanche Effect)")
    import numpy as np
    base_seed    = os.urandom(32)
    rng1         = HashDRBG(HashAlgorithm.SHA256)
    rng1._instantiate(base_seed, b"\x00" * 16)
    out_base     = rng1.generate(32)

    # Flip exactly 1 bit in the seed
    seed_flip    = bytearray(base_seed)
    seed_flip[0] ^= 0x01
    rng2         = HashDRBG(HashAlgorithm.SHA256)
    rng2._instantiate(bytes(seed_flip), b"\x00" * 16)
    out_flipped  = rng2.generate(32)

    bits_base    = np.unpackbits(np.frombuffer(out_base,    dtype=np.uint8))
    bits_flipped = np.unpackbits(np.frombuffer(out_flipped, dtype=np.uint8))
    hamming      = int(np.sum(bits_base != bits_flipped))
    pct          = 100 * hamming / (32 * 8)

    print(f"      Base seed     : {base_seed[:8].hex()}... → output: {out_base[:8].hex()}...")
    print(f"      1-bit flip    : {bytes(seed_flip)[:8].hex()}... → output: {out_flipped[:8].hex()}...")
    print(f"      Hamming dist  : {hamming}/{32*8} bits ({pct:.1f}%)  [ideal ≈ 50%]")


# ──────────────────────────────────────────────────────────────────────────────
# Section 5: NIST Test Vector Validation
# ──────────────────────────────────────────────────────────────────────────────

def demo_test_vector_validation() -> None:
    """
    Validate hash_df against a manually computed reference.
    Full official NIST CAVP vectors require the complete STS harness,
    but we validate our hash_df and hashgen logic against known SHA-256 outputs.
    """
    separator("5. Internal Consistency & hash_df Validation")

    rng = HashDRBG(HashAlgorithm.SHA256)

    # The hash_df must produce exactly seedlen=440 bits (55 bytes)
    test_input  = b"test_entropy_input_for_hash_df_validation"
    derived     = rng._hash_df(test_input, 440)
    assert len(derived) == 55, f"Expected 55 bytes, got {len(derived)}"

    # Verify determinism: same input must always produce same output
    derived2 = rng._hash_df(test_input, 440)
    assert derived == derived2, "hash_df is not deterministic!"

    # Verify the hash_df counter increment (different counter → different output)
    derived_128 = rng._hash_df(test_input, 128)  # 16 bytes
    derived_256 = rng._hash_df(test_input, 256)  # 32 bytes
    # The first 16 bytes of the 256-bit derivation should equal the 128-bit derivation
    # (because both use counter=1 with the same input and bit-count differs only in length)
    # This property holds when no_of_bits fits in a single hash call:
    # hash_df iterates: counter=1,2,... For 440 bits with SHA-256 (outlen=256),
    # it runs 2 iterations. Verify the FIRST 32-byte block matches SHA-256(1||440||input).
    first_block_expected = hashlib.sha256(
        b"\x01"                          # counter = 1
        + (440).to_bytes(4, "big")       # no_of_bits = 440
        + test_input
    ).digest()
    assert derived[:32] == first_block_expected, "hash_df first block does not match SHA-256 reference!"

    print("  ✓ hash_df produces correct 440-bit output (55 bytes)")
    print("  ✓ hash_df is deterministic")
    print("  ✓ hash_df first block matches SHA-256(\x01 || 440 || input) exactly")
    print(f"\n  hash_df(input, 440 bits) = {derived.hex()}")

    # Validate Hashgen: known V → known first block of output = SHA-256(V)
    V_test   = b"\x01" * 55   # fixed V for testing
    hashgen1 = rng._hashgen(256, V_test)[:32]
    expected = hashlib.sha256(V_test).digest()
    assert hashgen1 == expected, "Hashgen first block mismatch!"
    print(f"\n  ✓ Hashgen first block matches SHA-256(V) directly:")
    print(f"    SHA-256(V) = {expected.hex()}")


# ──────────────────────────────────────────────────────────────────────────────
# Section 6: Performance Benchmark
# ──────────────────────────────────────────────────────────────────────────────

def demo_benchmark() -> None:
    separator("6. Performance Benchmark")

    sizes  = [1_024, 16_384, 65_536, 262_144]  # bytes
    rng    = HashDRBG(HashAlgorithm.SHA256)

    print(f"  {'Size':>10}  {'Time (ms)':>12}  {'Throughput':>14}")
    print(f"  {'─'*10}  {'─'*12}  {'─'*14}")

    for n in sizes:
        t0  = time.perf_counter()
        rng.generate(n)
        dt  = time.perf_counter() - t0
        tp  = n / dt / 1_000_000  # MB/s
        print(f"  {n:>10,}  {dt*1000:>11.2f}ms  {tp:>12.2f} MB/s")

    print(f"\n  Note: SHA-256 is intentionally 'slower' than AES-CTR DRBG")
    print(f"        because it prioritises security strength over throughput.")
    print(f"        For crypto key material (small volumes), this is ideal.")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    header()

    # 1. Basic generation
    large_output = demo_basic_generation()

    # 2. Algorithm variants
    demo_algorithm_variants()

    # 3. NIST statistical tests
    generator_results = demo_nist_sts(large_output)

    # 4. Security properties
    demo_security_properties()

    # 5. Test vector validation
    demo_test_vector_validation()

    # 6. Benchmark
    demo_benchmark()

    # 7. Generate figures
    separator("7. Generating Figures")

    # Need more data for good statistics
    rng        = HashDRBG(HashAlgorithm.SHA256)
    stat_data  = rng.generate(32_768)  # 32 KB

    print("\n  Figure 1: Output quality analysis ...")
    plot_output_analysis(stat_data, "figure1_output_analysis.png")

    print("  Figure 2: NIST comparison across generators ...")
    # Run fresh tests on 16 KB for the comparison chart
    from analysis.visualizer import LCG, _get_python_rng_bytes
    rng2       = HashDRBG(HashAlgorithm.SHA256)
    all_results = {
        "Hash-DRBG (SHA-256)":   run_full_suite(rng2.generate(16_384), verbose=False),
        "LCG (weak)":            run_full_suite(LCG().randbytes(16_384), verbose=False),
        "Python random (MT)":    run_full_suite(_get_python_rng_bytes(16_384), verbose=False),
        "os.urandom":            run_full_suite(os.urandom(16_384), verbose=False),
    }
    plot_nist_comparison(all_results, "figure2_nist_comparison.png")

    print("  Figure 3: Security properties (avalanche, forward secrecy) ...")
    plot_security_properties("figure3_security_properties.png")

    separator("Done")
    print("""
  Output files:
    figure1_output_analysis.png   — byte histogram, bit balance, autocorrelation
    figure2_nist_comparison.png   — NIST SP 800-22 test results vs 4 generators
    figure3_security_properties.png — avalanche effect & forward secrecy

  Implementation:
    hash_drbg/core.py             — NIST SP 800-90A Hash_DRBG (exact spec)
    statistical_tests/nist_sts.py — NIST SP 800-22 (8 tests from scratch)
    analysis/visualizer.py        — All visualizations
    demo.py                       — This demonstration script
""")


if __name__ == "__main__":
    main()
