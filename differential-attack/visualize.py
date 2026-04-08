import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import Counter
from toy_cipher import ToyCipher
from des import SimplifiedDES
from pairs import generate_differential_pairs, find_good_differential
from attack import differential_attack, measure_attack_effectiveness


def plot_differential_distribution():
    """Show how input differences propagate to output differences."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    cipher = ToyCipher(key=0x3FF)
    deltas = [0x01, 0x40, 0x80]

    for idx, delta in enumerate(deltas):
        pairs = generate_differential_pairs(cipher, num_pairs=1000, delta=delta)
        output_diffs = [c ^ c_prime for _, _, c, c_prime in pairs]

        diff_counts = Counter(output_diffs)
        values, counts = zip(*sorted(diff_counts.items()))

        axes[idx].bar(values, counts, color="steelblue", alpha=0.7)
        axes[idx].set_xlabel("Output XOR Difference")
        axes[idx].set_ylabel("Count")
        axes[idx].set_title(f"Input Δ = 0x{delta:02X}")

    plt.suptitle(
        "Differential Distribution for ToyCipher", fontsize=14, fontweight="bold"
    )
    plt.tight_layout()
    plt.savefig("differential-dist.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("Created: differential-dist.png")


def plot_attack_effectiveness():
    """Show success rate vs number of pairs."""
    fig, ax = plt.subplots(figsize=(10, 6))

    test_key = 0x1FF
    pair_counts = [5, 10, 15, 20, 30, 50, 100]
    results = measure_attack_effectiveness(
        ToyCipher, test_key, num_trials=20, pair_counts=pair_counts
    )

    pairs_list = list(results.keys())
    success_rates = [results[p] * 100 for p in pairs_list]

    ax.plot(
        pairs_list, success_rates, "o-", linewidth=2, markersize=8, color="darkgreen"
    )
    ax.fill_between(pairs_list, 0, success_rates, alpha=0.2, color="green")

    ax.set_xlabel("Number of Plaintext Pairs", fontsize=12)
    ax.set_ylabel("Success Rate (%)", fontsize=12)
    ax.set_title(
        "Differential Attack Effectiveness\n(ToyCipher, 10-bit key)",
        fontsize=14,
        fontweight="bold",
    )
    ax.set_ylim(0, 105)
    ax.grid(True, alpha=0.3)

    for x, y in zip(pairs_list, success_rates):
        ax.annotate(f"{y:.0f}%", (x, y + 3), ha="center", fontsize=10)

    plt.savefig("attack-success.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("Created: attack-success.png")


def plot_differential_characteristic():
    """Visualize the differential characteristic through rounds."""
    fig, ax = plt.subplots(figsize=(12, 6))

    delta = 0x80
    cipher = ToyCipher(key=0x3FF)

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
        "Differential Characteristic\nToyCipher with Δ = 0x80",
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
    plt.savefig("characteristic.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("Created: characteristic.png")


def plot_key_recovery_demo():
    """Show step-by-step key recovery."""
    fig, axes = plt.subplots(2, 2, figsize=(12, 10))

    test_key = 0x2AB
    cipher = ToyCipher(test_key)

    ax = axes[0, 0]
    key_scores = []
    for key in range(1024):
        test_cipher = ToyCipher(key)
        score = sum(
            1
            for _ in range(50)
            for p in [np.random.randint(0, 256)]
            if test_cipher.encrypt(p) == cipher.encrypt(p)
        )
        key_scores.append(score)

    ax.plot(range(1024), key_scores, "b-", alpha=0.5)
    ax.axvline(x=test_key, color="r", linewidth=2, label=f"True key: 0x{test_key:03X}")
    ax.set_xlabel("Key Candidate")
    ax.set_ylabel("Match Score")
    ax.set_title("Key Search Space")
    ax.legend()

    ax = axes[0, 1]
    SBOX = [12, 5, 2, 15, 0, 14, 4, 1, 9, 8, 13, 6, 11, 10, 3, 7]
    diff_table = np.zeros((16, 16))
    for i in range(16):
        for j in range(16):
            diff_table[i][j] = SBOX[i] ^ SBOX[j]

    im = ax.imshow(diff_table, cmap="YlOrRd")
    ax.set_xlabel("Input XOR")
    ax.set_ylabel("Output XOR")
    ax.set_title("S-Box Differential Table")
    plt.colorbar(im, ax=ax)

    ax = axes[1, 0]
    pairs = generate_differential_pairs(cipher, num_pairs=200, delta=0x80)
    output_diffs = [c ^ c_prime for _, _, c, c_prime in pairs]
    ax.hist(output_diffs, bins=16, color="teal", alpha=0.7, edgecolor="black")
    ax.set_xlabel("Output XOR Difference")
    ax.set_ylabel("Count")
    ax.set_title("Output Difference Distribution (200 pairs)")

    ax = axes[1, 1]
    complexities = [(32, "Subkey K1"), (32, "Subkey K2"), (1024, "Full brute force")]
    methods, complexity = zip(*complexities)
    bars = ax.bar(methods, complexity, color=["#2ecc71", "#3498db", "#e74c3c"])
    ax.set_ylabel("Key Space Size")
    ax.set_title("Attack Complexity Comparison")
    for bar, c in zip(bars, complexity):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 10,
            str(c),
            ha="center",
            fontsize=11,
        )

    plt.suptitle(
        "Differential Attack Analysis Dashboard", fontsize=16, fontweight="bold", y=1.02
    )
    plt.tight_layout()
    plt.savefig("attack-dashboard.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("Created: attack-dashboard.png")


if __name__ == "__main__":
    print("Generating visualizations...")
    plot_differential_distribution()
    plot_attack_effectiveness()
    plot_differential_characteristic()
    plot_key_recovery_demo()
    print("\nAll visualizations complete!")
