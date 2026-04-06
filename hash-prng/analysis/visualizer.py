"""
analysis/visualizer.py
======================
Professional visualizations for the Hash-DRBG project.

Produces 3 publication-quality figures:
    Figure 1: Output quality analysis (byte histogram, bit balance, autocorrelation)
    Figure 2: NIST SP 800-22 test results comparison (Hash-DRBG vs LCG vs random.random)
    Figure 3: Security properties demonstration (forward secrecy, state update)
"""

import math
import os
import random
import struct
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.ticker import MaxNLocator
from typing import List, Dict, Optional
from statistical_tests.nist_sts import TestResult

# Use non-interactive backend for file output
matplotlib.use("Agg")

# ---------------------------------------------------------------------------
# Style constants
# ---------------------------------------------------------------------------

PALETTE = {
    "hash_drbg": "#1D9E75",  # teal  — our implementation
    "lcg":       "#D85A30",  # coral — weak LCG
    "python_rng":"#7F77DD",  # purple — Python random (Mersenne Twister)
    "os_random": "#378ADD",  # blue  — os.urandom (true entropy reference)
    "neutral":   "#888780",  # gray
    "pass":      "#1D9E75",
    "fail":      "#D85A30",
    "bg":        "#FAFAF8",
    "grid":      "#E5E3DE",
}

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.color": PALETTE["grid"],
    "grid.linewidth": 0.6,
    "figure.facecolor": PALETTE["bg"],
    "axes.facecolor": PALETTE["bg"],
    "axes.labelcolor": "#3d3d3a",
    "xtick.color": "#5F5E5A",
    "ytick.color": "#5F5E5A",
    "axes.titleweight": "bold",
    "axes.titlesize": 13,
})


# ---------------------------------------------------------------------------
# Helper: Weak PRNGs for comparison
# ---------------------------------------------------------------------------

class LCG:
    """
    Linear Congruential Generator — classically broken PRNG.
    Parameters from Numerical Recipes (weak, predictable after 2 outputs).
        X_{n+1} = (a * X_n + c) mod m
    """
    a = 1664525
    c = 1013904223
    m = 2 ** 32

    def __init__(self, seed: Optional[int] = None):
        self.state = seed or int.from_bytes(os.urandom(4), "big")

    def getrandbits(self, n: int) -> int:
        bits, count = 0, 0
        while count < n:
            self.state = (self.a * self.state + self.c) % self.m
            bits       = (bits << 32) | self.state
            count     += 32
        return bits >> (count - n)

    def randbytes(self, n: int) -> bytes:
        result = b""
        while len(result) < n:
            val     = (self.a * self.state + self.c) % self.m
            self.state = val
            result += struct.pack(">I", val)
        return result[:n]


def _get_python_rng_bytes(n: int) -> bytes:
    """Python standard random module (Mersenne Twister)."""
    rng = random.Random(os.urandom(32))
    return bytes(rng.getrandbits(8) for _ in range(n))


def _bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


# ---------------------------------------------------------------------------
# Figure 1: Output Quality Analysis
# ---------------------------------------------------------------------------

def plot_output_analysis(
    hash_drbg_output: bytes,
    filename: str = "figure1_output_analysis.png",
) -> None:
    """
    Three-panel analysis of a single generator's output:
      (a) Byte frequency histogram — should be flat (uniform distribution)
      (b) Sequential bit balance — should hover at 0.5
      (c) Autocorrelation function — should be near zero for all lags
    """
    n       = len(hash_drbg_output)
    bits    = _bytes_to_bits(hash_drbg_output)
    lcg     = LCG()
    lcg_out = lcg.randbytes(n)

    fig = plt.figure(figsize=(16, 12), facecolor=PALETTE["bg"])
    fig.suptitle(
        "Hash_DRBG Output Quality Analysis  (NIST SP 800-90A, SHA-256)",
        fontsize=16, fontweight="bold", y=0.98
    )

    gs = gridspec.GridSpec(3, 2, figure=fig, hspace=0.42, wspace=0.35)

    # ── (a) Byte frequency histogram ──────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, :])
    byte_counts_h  = np.bincount(np.frombuffer(hash_drbg_output, dtype=np.uint8), minlength=256)
    byte_counts_l  = np.bincount(np.frombuffer(lcg_out,          dtype=np.uint8), minlength=256)
    x              = np.arange(256)
    expected       = n / 256

    ax1.bar(x, byte_counts_h, width=1.2, color=PALETTE["hash_drbg"], alpha=0.8, label="Hash-DRBG (SHA-256)")
    ax1.axhline(expected, color=PALETTE["neutral"], lw=1.5, linestyle="--", label=f"Expected = {expected:.1f}")
    ax1.set_xlabel("Byte value (0–255)")
    ax1.set_ylabel("Count")
    ax1.set_title("(a) Byte Frequency Distribution — should be flat for a uniform random generator")
    ax1.legend(fontsize=10)
    ax1.set_xlim(-1, 256)

    # Chi-squared uniformity score
    chi2_h = np.sum((byte_counts_h - expected) ** 2 / expected)
    chi2_l = np.sum((byte_counts_l - expected) ** 2 / expected)
    ax1.text(
        0.99, 0.97,
        f"χ² Hash-DRBG = {chi2_h:.1f}   LCG = {chi2_l:.1f}   (ideal ≈ 255)",
        transform=ax1.transAxes, ha="right", va="top",
        fontsize=10, color="#3d3d3a",
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.7, edgecolor=PALETTE["grid"]),
    )

    # ── (b) Sequential bit balance (sliding window) ───────────────────────
    ax2 = fig.add_subplot(gs[1, 0])
    window = 256
    ratios_h = [
        np.mean(bits[i: i + window])
        for i in range(0, len(bits) - window, window)
    ]
    lcg_bits = _bytes_to_bits(lcg_out)
    ratios_l = [
        np.mean(lcg_bits[i: i + window])
        for i in range(0, len(lcg_bits) - window, window)
    ]

    ax2.plot(ratios_h, color=PALETTE["hash_drbg"], lw=1.2, label="Hash-DRBG")
    ax2.plot(ratios_l, color=PALETTE["lcg"],       lw=1.2, label="LCG (weak)", alpha=0.7)
    ax2.axhline(0.5, color=PALETTE["neutral"], lw=1.5, linestyle="--")
    ax2.set_ylim(0.35, 0.65)
    ax2.set_xlabel(f"Window index (each = {window} bits)")
    ax2.set_ylabel("Proportion of 1s")
    ax2.set_title("(b) Sequential Bit Balance")
    ax2.legend(fontsize=9)

    # ── (c) Autocorrelation ───────────────────────────────────────────────
    ax3 = fig.add_subplot(gs[1, 1])
    max_lag = 50
    bits_pm  = bits.astype(float) * 2 - 1  # Map {0,1} → {-1,+1}
    mean_val = np.mean(bits_pm)
    variance = np.var(bits_pm)
    acf = [
        np.mean((bits_pm[: len(bits_pm) - k] - mean_val) *
                (bits_pm[k:]                - mean_val)) / variance
        for k in range(1, max_lag + 1)
    ]

    lags = np.arange(1, max_lag + 1)
    confidence = 1.96 / math.sqrt(len(bits))  # 95% confidence band

    ax3.bar(lags, acf, color=PALETTE["hash_drbg"], alpha=0.8, width=0.7)
    ax3.axhline(+confidence, color=PALETTE["lcg"], lw=1.2, linestyle="--", label="±95% CI")
    ax3.axhline(-confidence, color=PALETTE["lcg"], lw=1.2, linestyle="--")
    ax3.axhline(0,           color=PALETTE["neutral"], lw=1.0)
    ax3.set_xlabel("Lag (bits)")
    ax3.set_ylabel("Autocorrelation")
    ax3.set_title("(c) Autocorrelation Function — should be near 0")
    ax3.legend(fontsize=9)

    # ── (d) Bit-level heatmap (8×8 blocks of 64 bits) ────────────────────
    ax4 = fig.add_subplot(gs[2, 0])
    sample_bits = bits[:4096].reshape(64, 64)
    ax4.imshow(sample_bits, cmap="RdYlGn", aspect="auto", interpolation="nearest")
    ax4.set_xlabel("Bit position within row")
    ax4.set_ylabel("Row (block of 64 bits)")
    ax4.set_title("(d) Bit Heatmap — first 4 096 bits\n(green=1, red=0, uniform texture = random)")
    ax4.set_xticks([])
    ax4.set_yticks([])

    # ── (e) Cumulative bit balance convergence ────────────────────────────
    ax5 = fig.add_subplot(gs[2, 1])
    cumsum   = np.cumsum(bits_pm)
    n_range  = np.arange(1, len(bits_pm) + 1)
    running_mean = cumsum / n_range

    ax5.plot(n_range, running_mean, color=PALETTE["hash_drbg"], lw=1.0, label="Hash-DRBG")
    ax5.axhline(0, color=PALETTE["neutral"], lw=1.2, linestyle="--", label="Ideal (0.0)")
    # 3σ confidence bounds
    bounds = 3 / np.sqrt(n_range)
    ax5.fill_between(n_range, -bounds, +bounds, alpha=0.12, color=PALETTE["hash_drbg"])
    ax5.set_xscale("log")
    ax5.set_xlabel("Number of bits seen (log scale)")
    ax5.set_ylabel("Running mean of ±1 values")
    ax5.set_title("(e) Convergence to Mean — CLT verification")
    ax5.legend(fontsize=9)

    plt.savefig(filename, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close()
    print(f"  Saved → {filename}")


# ---------------------------------------------------------------------------
# Figure 2: NIST SP 800-22 Comparison Across Generators
# ---------------------------------------------------------------------------

def plot_nist_comparison(
    results_by_generator: Dict[str, List[TestResult]],
    filename: str = "figure2_nist_comparison.png",
) -> None:
    """
    Grouped bar chart comparing p-values across multiple generators
    for each NIST SP 800-22 test. The red dashed line at 0.01 marks
    the significance threshold α.
    """
    generators = list(results_by_generator.keys())
    test_names = [r.name for r in list(results_by_generator.values())[0]]
    n_tests    = len(test_names)
    n_gen      = len(generators)

    colors = [
        PALETTE["hash_drbg"],
        PALETTE["lcg"],
        PALETTE["python_rng"],
        PALETTE["os_random"],
    ][:n_gen]

    fig, axes = plt.subplots(1, 2, figsize=(18, 8), facecolor=PALETTE["bg"])
    fig.suptitle(
        "NIST SP 800-22 Statistical Test Suite — Generator Comparison",
        fontsize=15, fontweight="bold",
    )

    # ── Left: p-value bar chart ───────────────────────────────────────────
    ax = axes[0]
    width  = 0.75 / n_gen
    x      = np.arange(n_tests)

    for i, (gen, results) in enumerate(results_by_generator.items()):
        p_values = [r.p_value for r in results]
        offset   = (i - n_gen / 2 + 0.5) * width
        bars     = ax.bar(x + offset, p_values, width, color=colors[i], alpha=0.85, label=gen)

    ax.axhline(ALPHA := 0.01, color="#D85A30", lw=1.8, linestyle="--", label=f"α = {ALPHA} (threshold)")
    ax.set_xticks(x)
    ax.set_xticklabels(
        [n.replace(" (", "\n(") for n in test_names],
        rotation=35, ha="right", fontsize=8.5
    )
    ax.set_ylabel("p-value")
    ax.set_title("p-values per test (higher = more random)\np-value < 0.01 → FAIL", pad=10)
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=9)

    # ── Right: pass/fail heatmap ──────────────────────────────────────────
    ax2 = axes[1]
    matrix = np.array([
        [1 if r.passed else 0 for r in results_by_generator[g]]
        for g in generators
    ], dtype=float)

    im = ax2.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
    ax2.set_xticks(range(n_tests))
    ax2.set_xticklabels(
        [n.split(" (")[0] for n in test_names],
        rotation=40, ha="right", fontsize=8.5
    )
    ax2.set_yticks(range(n_gen))
    ax2.set_yticklabels(generators, fontsize=10)
    ax2.set_title("Pass / Fail Heatmap\n(green = PASS, red = FAIL)", pad=10)

    # Annotate cells
    for i in range(n_gen):
        for j in range(n_tests):
            pv = results_by_generator[generators[i]][j].p_value
            ax2.text(
                j, i, f"{pv:.3f}",
                ha="center", va="center",
                fontsize=7.5, color="white" if matrix[i, j] == 0 else "#173404",
            )

    plt.colorbar(im, ax=ax2, fraction=0.03, label="Pass (1) / Fail (0)")
    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close()
    print(f"  Saved → {filename}")


# ---------------------------------------------------------------------------
# Figure 3: Security Properties Demonstration
# ---------------------------------------------------------------------------

def plot_security_properties(
    filename: str = "figure3_security_properties.png",
) -> None:
    """
    Demonstrates two cryptographic security properties of Hash-DRBG:

    (a) Backtracking resistance: after a state update, previous outputs
        cannot be reconstructed. We show bit-level Hamming distance
        between pre-update and post-update output windows.

    (b) Sensitivity to seed (avalanche effect): changing a single bit
        in the seed produces a radically different output — measured by
        Hamming distance between output pairs with seeds differing by 1 bit.
    """
    import hashlib, os
    from hash_drbg.core import HashDRBG, HashAlgorithm

    fig, axes = plt.subplots(1, 2, figsize=(16, 7), facecolor=PALETTE["bg"])
    fig.suptitle(
        "Hash_DRBG Security Property Analysis",
        fontsize=15, fontweight="bold",
    )

    # ── (a) Sensitivity to seed: Avalanche effect ─────────────────────────
    ax = axes[0]
    n_flips  = 128   # flip each of first 128 seed bits
    n_output = 256   # compare this many output bits

    # Reference seed
    base_seed = os.urandom(32)

    base_rng    = HashDRBG(HashAlgorithm.SHA256)
    base_rng._instantiate(base_seed, b"\x00" * 16)
    base_output = base_rng.generate(n_output // 8)
    base_bits   = np.unpackbits(np.frombuffer(base_output, dtype=np.uint8))

    distances = []
    for bit_pos in range(n_flips):
        # Flip one bit in the seed
        seed_bytes   = bytearray(base_seed)
        byte_idx     = bit_pos // 8
        bit_off      = 7 - (bit_pos % 8)
        seed_bytes[byte_idx] ^= (1 << bit_off)

        flipped_rng = HashDRBG(HashAlgorithm.SHA256)
        flipped_rng._instantiate(bytes(seed_bytes), b"\x00" * 16)
        flipped_out  = flipped_rng.generate(n_output // 8)
        flipped_bits = np.unpackbits(np.frombuffer(flipped_out, dtype=np.uint8))

        hamming = np.sum(base_bits != flipped_bits)
        distances.append(hamming)

    ax.bar(range(n_flips), distances, color=PALETTE["hash_drbg"], alpha=0.8, width=1.0)
    ax.axhline(n_output / 2, color=PALETTE["lcg"], lw=1.8, linestyle="--",
               label=f"Ideal = {n_output//2} bits ({50}%)")
    ax.set_xlabel("Seed bit position flipped")
    ax.set_ylabel("Hamming distance in output (bits)")
    ax.set_title(
        "(a) Avalanche Effect — Seed Sensitivity\n"
        "Each bar: 1-bit seed change → output distance from baseline",
        pad=8
    )
    ax.set_ylim(0, n_output)
    ax.legend(fontsize=9)

    mean_dist = np.mean(distances)
    ax.text(
        0.99, 0.04,
        f"Mean = {mean_dist:.1f} bits ({100*mean_dist/n_output:.1f}%)\nIdeal = 50%",
        transform=ax.transAxes, ha="right", va="bottom", fontsize=9,
        bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.8, edgecolor=PALETTE["grid"]),
    )

    # ── (b) Forward secrecy: output divergence after state update ─────────
    ax2 = axes[1]

    # Show that each generate() call produces completely independent output
    rng       = HashDRBG(HashAlgorithm.SHA256)
    n_calls   = 64
    chunk_sz  = 32  # bytes per call

    outputs   = [rng.generate(chunk_sz) for _ in range(n_calls)]
    bits_mat  = np.array([
        np.unpackbits(np.frombuffer(o, dtype=np.uint8)) for o in outputs
    ], dtype=np.float32)  # shape: (n_calls, chunk_sz*8)

    # Pairwise Hamming distances between consecutive outputs
    dists = []
    for i in range(n_calls - 1):
        d = np.sum(bits_mat[i] != bits_mat[i + 1])
        dists.append(d)

    ax2.plot(dists, color=PALETTE["hash_drbg"], lw=1.5, marker="o",
             markersize=3.5, label="Consecutive output distance")
    ax2.axhline(chunk_sz * 8 / 2, color=PALETTE["lcg"], lw=1.8,
                linestyle="--", label=f"Expected = {chunk_sz*4} bits (50%)")
    ax2.set_xlabel("Generate call index")
    ax2.set_ylabel("Hamming distance to next output (bits)")
    ax2.set_title(
        "(b) Output Independence / Forward Secrecy\n"
        "Consecutive generate() outputs should be unrelated",
        pad=8
    )
    ax2.legend(fontsize=9)

    # Correlation matrix subplot inset
    corr = np.corrcoef(bits_mat)
    inset = ax2.inset_axes([0.62, 0.05, 0.36, 0.36])
    inset.imshow(corr, cmap="RdBu_r", vmin=-0.15, vmax=0.15)
    inset.set_title("Output\ncorr. matrix", fontsize=7.5, pad=2)
    inset.set_xticks([])
    inset.set_yticks([])

    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches="tight", facecolor=PALETTE["bg"])
    plt.close()
    print(f"  Saved → {filename}")
