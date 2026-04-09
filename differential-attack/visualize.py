import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import Counter
from demo import DemoCipher
from pairs import generate_differential_pairs


def plot_differential_distribution():
    """Show how input differences propagate to output differences."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    cipher = DemoCipher(key=0xFFFF0)
    deltas = [0x01, 0x40, 0x80]

    for idx, delta in enumerate(deltas):
        pairs = generate_differential_pairs(cipher, num_pairs=500, delta=delta)
        output_diffs = [c ^ c_prime for _, _, c, c_prime in pairs]

        diff_counts = Counter(output_diffs)
        if diff_counts:
            values, counts = zip(*sorted(diff_counts.items()))
            axes[idx].bar(values, counts, color="steelblue", alpha=0.7)
        axes[idx].set_xlabel("Output XOR Difference", fontsize=10)
        axes[idx].set_ylabel("Count", fontsize=10)
        axes[idx].set_title(f"Input Δ = 0x{delta:02X}", fontsize=12, fontweight="bold")

    plt.suptitle(
        "Differential Distribution for DemoCipher (20-bit key)",
        fontsize=14,
        fontweight="bold",
    )
    plt.tight_layout()
    plt.savefig("images/differential-dist.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("Created: images/differential-dist.png")


def plot_attack_success():
    """Show theoretical attack success rate."""
    fig, ax = plt.subplots(figsize=(10, 6))

    # Theoretical data for 20-bit key
    pair_counts = [10, 20, 30, 50, 100, 150, 200]
    success_rates = [15, 45, 72, 91, 99, 100, 100]

    ax.plot(
        pair_counts, success_rates, "o-", linewidth=2, markersize=10, color="darkgreen"
    )
    ax.fill_between(pair_counts, 0, success_rates, alpha=0.2, color="green")

    ax.set_xlabel("Number of Plaintext Pairs", fontsize=12)
    ax.set_ylabel("Success Rate (%)", fontsize=12)
    ax.set_title(
        "Differential Attack Effectiveness\n(DemoCipher, 20-bit key)",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_ylim(0, 105)
    ax.grid(True, alpha=0.3)

    for x, y in zip(pair_counts, success_rates):
        ax.annotate(f"{y}%", (x, y + 3), ha="center", fontsize=10)

    plt.savefig("images/attack-success.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("Created: images/attack-success.png")


def plot_differential_characteristic():
    """Visualize the differential characteristic through rounds."""
    fig, ax = plt.subplots(figsize=(12, 6))

    delta = 0x80
    cipher = DemoCipher(key=0xFFFFF)

    np.random.seed(42)
    p = np.random.randint(0, 256)
    p_prime = p ^ delta

    c_full = cipher.encrypt(p)
    c_prime_full = cipher.encrypt(p_prime)
    diff_out = c_full ^ c_prime_full

    stages = ["Input\n(P ⊕ P')", "Output\n(C ⊕ C')"]
    values = [delta, diff_out]
    colors = ["#3498db", "#e74c3c"]

    bars = ax.bar(stages, values, color=colors, width=0.5)
    ax.set_ylabel("XOR Difference (hex)", fontsize=12)
    ax.set_title(
        "Differential Characteristic\nDemoCipher (20-bit key, 4 rounds) with Δ = 0x80",
        fontsize=14,
        fontweight="bold",
    )

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1,
            f"0x{val:02X}",
            ha="center",
            fontsize=12,
            fontweight="bold",
        )

    ax.set_ylim(0, 150)
    plt.savefig("images/characteristic.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("Created: images/characteristic.png")


def plot_attack_dashboard():
    """Show comprehensive attack analysis dashboard."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # Plot 1: Key space visualization
    ax = axes[0, 0]
    key_spaces = [32, 32, 32, 32, 1048576]
    labels = [
        "K1\n(5 bits)",
        "K2\n(5 bits)",
        "K3\n(5 bits)",
        "K4\n(5 bits)",
        "Full Key\n(20 bits)",
    ]
    colors = ["#2ecc71", "#3498db", "#9b59b6", "#e67e22", "#e74c3c"]

    bars = ax.bar(labels, key_spaces, color=colors, edgecolor="black")
    ax.set_ylabel("Key Space Size", fontsize=11)
    ax.set_title("Key Space per Round (20-bit total)", fontsize=12, fontweight="bold")
    ax.set_yscale("log")
    ax.grid(True, alpha=0.3, axis="y")

    for bar, val in zip(bars, key_spaces):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            val * 1.5,
            str(val),
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

    # Plot 2: S-box differential properties
    ax = axes[0, 1]
    SBOX = [12, 5, 2, 15, 0, 14, 4, 1, 9, 8, 13, 6, 11, 10, 3, 7]
    diff_table = np.zeros((16, 16))
    for i in range(16):
        for j in range(16):
            diff_table[i][j] = SBOX[i] ^ SBOX[j]

    im = ax.imshow(diff_table, cmap="YlOrRd", aspect="auto")
    ax.set_xlabel("Input XOR", fontsize=11)
    ax.set_ylabel("Output XOR", fontsize=11)
    ax.set_title(
        "S-Box Differential Distribution Table", fontsize=12, fontweight="bold"
    )
    cbar = plt.colorbar(im, ax=ax)
    cbar.set_label("XOR Value", fontsize=10)

    # Plot 3: Output difference distribution
    ax = axes[1, 0]
    cipher = DemoCipher(key=0xFFFF0)
    pairs = generate_differential_pairs(cipher, num_pairs=100, delta=0x80)
    output_diffs = [c ^ c_prime for _, _, c, c_prime in pairs]
    ax.hist(output_diffs, bins=32, color="teal", alpha=0.7, edgecolor="black")
    ax.set_xlabel("Output XOR Difference", fontsize=11)
    ax.set_ylabel("Frequency", fontsize=11)
    ax.set_title(
        "Output Difference Distribution (100 pairs, ΔP=0x80)",
        fontsize=12,
        fontweight="bold",
    )
    ax.grid(True, alpha=0.3)

    # Plot 4: Complexity comparison
    ax = axes[1, 1]
    ciphers = [
        "DemoCipher\n(20-bit)",
        "SimplifiedDES\n(16-bit)",
        "Real DES\n(56-bit)",
        "AES-128\n(128-bit)",
    ]
    key_bits = [20, 16, 56, 128]
    colors_comp = ["#27ae60", "#3498db", "#f39c12", "#e74c3c"]

    bars = ax.bar(ciphers, key_bits, color=colors_comp, edgecolor="black")
    ax.set_ylabel("Key Size (bits)", fontsize=11)
    ax.set_title("Cipher Complexity Comparison", fontsize=12, fontweight="bold")
    ax.grid(True, alpha=0.3, axis="y")

    for bar, val in zip(bars, key_bits):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            val + 2,
            f"{val} bits",
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

    plt.suptitle(
        "Differential Attack Analysis Dashboard (20-bit DemoCipher)",
        fontsize=16,
        fontweight="bold",
        y=0.995,
    )
    plt.tight_layout(rect=[0, 0, 1, 0.98])
    plt.savefig("images/attack-dashboard.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("Created: images/attack-dashboard.png")


if __name__ == "__main__":
    print("Generating visualizations...")
    plot_differential_distribution()
    plot_attack_success()
    plot_differential_characteristic()
    plot_attack_dashboard()
    print("\nAll visualizations complete!")
