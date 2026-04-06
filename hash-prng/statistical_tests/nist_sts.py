"""
NIST SP 800-22 Rev 1a — Statistical Test Suite for Randomness
==============================================================
Reference: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf

Implements 8 of the 15 NIST tests directly from scratch (no external STS library).
P-value threshold: 0.01 (sequences with p-value < 0.01 are considered non-random).

Tests implemented:
    1.  Frequency (Monobit) Test
    2.  Frequency Test within a Block
    3.  Runs Test
    4.  Longest Run of Ones in a Block
    5.  Discrete Fourier Transform (Spectral) Test
    6.  Approximate Entropy Test
    7.  Cumulative Sums Test
    8.  Serial Test
"""

import math
import numpy as np
from dataclasses import dataclass
from typing import List, Tuple
from scipy.special import erfc, gammainc, gammaln


@dataclass
class TestResult:
    name: str
    p_value: float
    passed: bool
    statistic: float
    description: str = ""


ALPHA = 0.01  # Significance level


def _bytes_to_bits(data: bytes) -> List[int]:
    """Convert a byte string to a list of bits (MSB first)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


# ---------------------------------------------------------------------------
# Test 1 — Frequency (Monobit) Test  [NIST Section 2.1]
# ---------------------------------------------------------------------------

def frequency_monobit_test(data: bytes) -> TestResult:
    """
    The proportion of 0s and 1s should be approximately equal.
    For a truly random sequence, Sn = Σ(2*xi - 1) should be close to 0.

    H0 (null hypothesis): The sequence is random.
    """
    bits = _bytes_to_bits(data)
    n    = len(bits)

    S_n  = sum(2 * b - 1 for b in bits)  # +1 for 1, -1 for 0
    s_obs = abs(S_n) / math.sqrt(n)
    p_value = erfc(s_obs / math.sqrt(2))

    return TestResult(
        name="Frequency (Monobit)",
        p_value=float(p_value),
        passed=p_value >= ALPHA,
        statistic=s_obs,
        description=f"n={n}, Sn={S_n}, s_obs={s_obs:.4f}",
    )


# ---------------------------------------------------------------------------
# Test 2 — Block Frequency Test  [NIST Section 2.2]
# ---------------------------------------------------------------------------

def block_frequency_test(data: bytes, block_size: int = 128) -> TestResult:
    """
    The proportion of 1s within each M-bit block should be approximately 0.5.
    Uses chi-squared distribution to aggregate block-level deviations.
    """
    bits    = _bytes_to_bits(data)
    n       = len(bits)
    M       = block_size
    N       = n // M  # number of complete blocks

    if N < 1:
        return TestResult("Block Frequency", 0.0, False, 0.0, "Insufficient data")

    chi_sq = 0.0
    for i in range(N):
        block   = bits[i * M:(i + 1) * M]
        pi_i    = sum(block) / M
        chi_sq += (pi_i - 0.5) ** 2

    chi_sq  *= 4 * M
    # NIST: p-value = igamc(N/2, chi_sq/2) = 1 - gammainc(N/2, chi_sq/2)
    p_value  = float(1.0 - gammainc(N / 2, chi_sq / 2))

    return TestResult(
        name="Block Frequency",
        p_value=float(p_value),
        passed=p_value >= ALPHA,
        statistic=chi_sq,
        description=f"N={N} blocks of M={M} bits, χ²={chi_sq:.4f}",
    )


# ---------------------------------------------------------------------------
# Test 3 — Runs Test  [NIST Section 2.3]
# ---------------------------------------------------------------------------

def runs_test(data: bytes) -> TestResult:
    """
    A 'run' is a maximal sequence of identical bits.
    The total number of runs (transitions between 0 and 1) should match
    what is expected for a uniform random sequence.
    """
    bits = _bytes_to_bits(data)
    n    = len(bits)
    pi   = sum(bits) / n  # proportion of 1s

    # Pre-test: if pi is too far from 0.5, runs test is invalid
    tau  = 2 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return TestResult(
            "Runs",
            0.0,
            False,
            0.0,
            f"Pre-test failed: π={pi:.4f}, τ={tau:.4f}. Sequence too biased.",
        )

    V_n  = sum(1 for i in range(n - 1) if bits[i] != bits[i + 1]) + 1
    numer = abs(V_n - 2 * n * pi * (1 - pi))
    denom = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = erfc(numer / denom)

    return TestResult(
        name="Runs",
        p_value=float(p_value),
        passed=p_value >= ALPHA,
        statistic=V_n,
        description=f"Vn={V_n}, π={pi:.4f}",
    )


# ---------------------------------------------------------------------------
# Test 4 — Longest Run of Ones in a Block  [NIST Section 2.4]
# ---------------------------------------------------------------------------

def longest_run_test(data: bytes) -> TestResult:
    """
    Tests whether the longest run of 1s in any M-bit block is consistent
    with what would be expected in a random sequence.
    Uses the chi-squared distribution with pre-defined probability values.
    """
    bits = _bytes_to_bits(data)
    n    = len(bits)

    # NIST Table 2: parameters based on sequence length
    if n < 128:
        return TestResult("Longest Run", 0.0, False, 0.0, "Sequence too short (need ≥128 bits)")

    if n < 6272:
        M, K = 8, 3
        probs = [0.2148, 0.3672, 0.2305, 0.1875]
        v_min = 1
    elif n < 750000:
        M, K = 128, 5
        probs = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
        v_min = 4
    else:
        M, K = 10000, 6
        probs = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
        v_min = 10

    N          = n // M
    v          = [0] * (K + 1)

    for i in range(N):
        block   = bits[i * M:(i + 1) * M]
        max_run = 0
        run     = 0
        for bit in block:
            if bit == 1:
                run    += 1
                max_run = max(max_run, run)
            else:
                run = 0
        idx      = min(max(max_run - v_min, 0), K)
        v[idx]  += 1

    chi_sq  = sum((v[i] - N * probs[i]) ** 2 / (N * probs[i]) for i in range(K + 1))
    p_value = 1 - _chi2_cdf(chi_sq, K)

    return TestResult(
        name="Longest Run of Ones",
        p_value=float(p_value),
        passed=p_value >= ALPHA,
        statistic=chi_sq,
        description=f"M={M}, N={N} blocks, χ²={chi_sq:.4f}",
    )


def _chi2_cdf(x: float, k: int) -> float:
    """Chi-squared CDF using the regularized incomplete gamma function."""
    return gammainc(k / 2, x / 2)


# ---------------------------------------------------------------------------
# Test 5 — DFT / Spectral Test  [NIST Section 2.6]
# ---------------------------------------------------------------------------

def spectral_dft_test(data: bytes) -> TestResult:
    """
    Detects periodic features in the sequence that would indicate non-randomness.
    Uses the Discrete Fourier Transform; the number of spectral peaks exceeding
    a threshold should be approximately 95% below that threshold for random data.
    """
    bits = _bytes_to_bits(data)
    n    = len(bits)

    # Map bits to ±1 signal
    X    = np.array([2 * b - 1 for b in bits], dtype=float)
    S    = np.abs(np.fft.fft(X))[: n // 2]  # first half of spectrum

    T          = math.sqrt(math.log(1 / 0.05) * n)  # threshold
    N_0        = 0.95 * n / 2              # expected number below threshold
    N_1        = np.sum(S < T)             # actual number below threshold
    d          = (N_1 - N_0) / math.sqrt(n * 0.95 * 0.05 / 4)
    p_value    = erfc(abs(d) / math.sqrt(2))

    return TestResult(
        name="Spectral (DFT)",
        p_value=float(p_value),
        passed=p_value >= ALPHA,
        statistic=d,
        description=f"N0={N_0:.1f}, N1={N_1}, d={d:.4f}",
    )


# ---------------------------------------------------------------------------
# Test 6 — Approximate Entropy Test  [NIST Section 2.12]
# ---------------------------------------------------------------------------

def approximate_entropy_test(data: bytes, m: int = 10) -> TestResult:
    """
    Compares the frequency of overlapping m-bit patterns with (m+1)-bit patterns.
    A random sequence maximises approximate entropy (approaches log(2) per bit).

    ApEn(m) = Φ(m) - Φ(m+1)
    """
    bits = _bytes_to_bits(data)
    n    = len(bits)

    def _phi(m_len: int) -> float:
        if m_len == 0:
            return 0.0
        # Count all overlapping m-length patterns (circular)
        counts: dict = {}
        for i in range(n):
            key = tuple(bits[i % n] for i in range(i, i + m_len))
            counts[key] = counts.get(key, 0) + 1
        return sum((c / n) * math.log(c / n) for c in counts.values())

    phi_m    = _phi(m)
    phi_m1   = _phi(m + 1)
    ap_en    = phi_m - phi_m1
    chi_sq   = 2 * n * (math.log(2) - ap_en)
    # NIST SP 800-22 eq: p-value = igamc(2^(m-1), chi_sq/2)
    # igamc(a, x) = 1 - gammainc(a, x)  [upper regularized incomplete gamma]
    p_value  = float(1.0 - gammainc(2 ** (m - 1), chi_sq / 2))

    return TestResult(
        name="Approximate Entropy",
        p_value=float(p_value),
        passed=p_value >= ALPHA,
        statistic=ap_en,
        description=f"m={m}, ApEn={ap_en:.6f}, χ²={chi_sq:.4f}",
    )


# ---------------------------------------------------------------------------
# Test 7 — Cumulative Sums Test  [NIST Section 2.13]
# ---------------------------------------------------------------------------

def cumulative_sums_test(data: bytes, forward: bool = True) -> TestResult:
    """
    Tests whether the cumulative sum (random walk) of the ±1 sequence
    is too large or too small relative to what is expected for random data.
    """
    bits  = _bytes_to_bits(data)
    n     = len(bits)

    X     = [2 * b - 1 for b in bits]
    if not forward:
        X = X[::-1]

    S     = np.cumsum(X)
    z     = int(np.max(np.abs(S)))

    # Compute p-value using the formula from NIST
    def _sum_term(k_range):
        total = 0.0
        for k in k_range:
            total += (
                _normal_cdf((4 * k + 1) * z / math.sqrt(n))
                - _normal_cdf((4 * k - 1) * z / math.sqrt(n))
            )
        return total

    k_range1 = range(int((-n / z + 1) / 4), int((n / z - 1) / 4) + 1)
    k_range2 = range(int((-n / z - 3) / 4), int((n / z - 1) / 4) + 1)

    p_value = 1.0 - _sum_term(k_range1) + _sum_term(k_range2)

    direction = "forward" if forward else "backward"
    return TestResult(
        name=f"Cumulative Sums ({direction})",
        p_value=float(p_value),
        passed=p_value >= ALPHA,
        statistic=z,
        description=f"z={z}, n={n}",
    )


def _normal_cdf(x: float) -> float:
    return 0.5 * erfc(-x / math.sqrt(2))


# ---------------------------------------------------------------------------
# Test 8 — Serial Test  [NIST Section 2.11]
# ---------------------------------------------------------------------------

def serial_test(data: bytes, m: int = 16) -> TestResult:
    """
    Determines whether the number of occurrences of 2^m m-bit overlapping
    patterns is approximately the same as expected for a random sequence.
    """
    bits = _bytes_to_bits(data)
    n    = len(bits)

    def _psi_sq(m_len: int) -> float:
        if m_len <= 0:
            return 0.0
        counts: dict = {}
        for i in range(n):
            key = tuple(bits[(i + j) % n] for j in range(m_len))
            counts[key] = counts.get(key, 0) + 1
        return (2 ** m_len / n) * sum(c ** 2 for c in counts.values()) - n

    delta1 = _psi_sq(m) - _psi_sq(m - 1)
    delta2 = _psi_sq(m) - 2 * _psi_sq(m - 1) + _psi_sq(m - 2)

    p1 = 1 - _chi2_cdf(delta1, 2 ** (m - 1))
    p2 = 1 - _chi2_cdf(delta2, 2 ** (m - 2))

    p_value = min(p1, p2)
    return TestResult(
        name="Serial",
        p_value=float(p_value),
        passed=p_value >= ALPHA,
        statistic=delta1,
        description=f"m={m}, ∇ψ²={delta1:.4f}, ∇²ψ²={delta2:.4f}",
    )


# ---------------------------------------------------------------------------
# Full Suite Runner
# ---------------------------------------------------------------------------

def run_full_suite(data: bytes, verbose: bool = True) -> List[TestResult]:
    """
    Run the complete statistical test suite on a byte sequence.
    Recommended minimum: 1,000 bytes (8,000 bits).
    """
    tests = [
        lambda: frequency_monobit_test(data),
        lambda: block_frequency_test(data, block_size=128),
        lambda: runs_test(data),
        lambda: longest_run_test(data),
        lambda: spectral_dft_test(data),
        lambda: approximate_entropy_test(data, m=10),
        lambda: cumulative_sums_test(data, forward=True),
        lambda: cumulative_sums_test(data, forward=False),
        lambda: serial_test(data, m=16),
    ]

    results = []
    for test_fn in tests:
        try:
            result = test_fn()
            results.append(result)
            if verbose:
                status = "✓ PASS" if result.passed else "✗ FAIL"
                print(f"  [{status}] {result.name:<35} p={result.p_value:.6f}  {result.description}")
        except Exception as e:
            results.append(TestResult(
                name="Error",
                p_value=0.0,
                passed=False,
                statistic=0.0,
                description=str(e),
            ))

    passed = sum(1 for r in results if r.passed)
    if verbose:
        print(f"\n  Result: {passed}/{len(results)} tests passed (α={ALPHA})")

    return results
