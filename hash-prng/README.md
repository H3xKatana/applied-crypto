# Hash-DRBG: Pseudo-Random Number Generator Based on Hash Functions

> **Academic project — Sujet 2**
> NIST SP 800-90A Rev 1 compliant implementation with full statistical validation

---

## Overview

This project implements a **cryptographically secure pseudo-random number generator (CSPRNG)** based on hash functions, following the exact specification of **NIST SP 800-90A Rev 1** (Section 10.1.1 — Hash_DRBG).

The output is statistically validated against **8 tests from NIST SP 800-22 Rev 1a**, all implemented from scratch without external STS libraries.

---

## Project Structure

```
hash_prng/
├── hash_drbg/
│   ├── __init__.py
│   └── core.py              ← Hash_DRBG: Instantiate, Generate, Reseed
├── statistical_tests/
│   ├── __init__.py
│   └── nist_sts.py          ← 8 NIST SP 800-22 tests from scratch
├── analysis/
│   └── visualizer.py        ← Matplotlib figures + comparison generators
├── demo.py                  ← Full end-to-end demonstration
└── README.md
```

---

## Supported Hash Algorithms

| Algorithm | Security Strength | Seedlen | Outlen |
|-----------|:-----------------:|:-------:|:------:|
| SHA-256   | 128-bit           | 440 bits | 256 bits |
| SHA-512   | 256-bit           | 888 bits | 512 bits |
| SHA-3-256 | 128-bit           | 440 bits | 256 bits |
| SHA-3-512 | 256-bit           | 888 bits | 512 bits |

---

## Algorithm — How It Works

### Core Primitives

**hash_df** (Hash Derivation Function — NIST §10.3.1)
```
for counter = 1, 2, ..., ceil(seedlen / outlen):
    temp += Hash(counter || no_of_bits || input_string)
return leftmost(seedlen) bits of temp
```

**Instantiate** (NIST §10.1.1.2)
```
seed = hash_df(entropy || nonce || personalization, seedlen)
V    = seed
C    = hash_df(0x00 || V, seedlen)
reseed_counter = 1
```

**Generate** (NIST §10.1.1.4)
```
# Produce output bits
returned_bits = Hashgen(requested_bits, V)

# Update internal state — forward secrecy
H    = Hash(0x03 || V)
V    = (V + H + C + reseed_counter) mod 2^seedlen
reseed_counter++
```

**Hashgen**
```
data = V
for i in 1..ceil(requested_bits / outlen):
    output += Hash(data)
    data = (data + 1) mod 2^seedlen
return leftmost(requested_bits) bits of output
```

---

## Security Properties

### 1. Forward Secrecy (Backtracking Resistance)
After each `generate()` call, V is updated:
```
V_new = (V + Hash(0x03 || V) + C + ctr) mod 2^440
```
An attacker who obtains the current state **cannot recover past outputs**, because inverting this update requires finding the preimage of SHA-256 — computationally infeasible.

### 2. Prediction Resistance
Output bits are produced as `Hash(V)` where `V` is kept secret. Given any number of outputs, recovering V requires breaking SHA-256's one-way property.

### 3. Avalanche Effect
Flipping a single bit in the seed changes **≈50% of output bits** (demonstrated in Figure 3).

---

## Statistical Validation — NIST SP 800-22 Rev 1a

All 8 implemented tests **pass** for Hash_DRBG (SHA-256), matching `os.urandom()` quality:

| Test | Hash-DRBG | LCG (weak) | MT19937 | os.urandom |
|------|:---------:|:----------:|:-------:|:----------:|
| Frequency (Monobit) | ✓ | ✓ | ✓ | ✓ |
| Block Frequency | ✓ | ✓ | ✓ | ✓ |
| Runs | ✓ | ✓ | ✓ | ✓ |
| Longest Run | ✓ | ✓ | ✓ | ✓ |
| **Spectral (DFT)** | **✓** | **✗ FAIL** | ✓ | ✓ |
| Approximate Entropy | ✓ | ✓ | ✓ | ✓ |
| Cumulative Sums | ✓ | ✓ | ✓ | ✓ |
| Serial | ✓ | ✓ | ✓ | ✓ |

The LCG **fails the Spectral (DFT) test** because its output has detectable periodic structure — this is the fundamental weakness of linear generators.

---

## Usage

```python
from hash_drbg.core import HashDRBG, HashAlgorithm

# Instantiate (entropy from OS automatically)
rng = HashDRBG(
    algorithm=HashAlgorithm.SHA256,
    personalization_string=b"my_application_v1",
)

# Generate random bytes
key        = rng.generate(32)    # 256-bit key
nonce      = rng.generate(12)    # 96-bit nonce
session_id = rng.generate(16)    # 128-bit session ID

# With per-call additional input (increases unpredictability)
token = rng.generate(32, additional_input=b"user_id=12345")

# Reseed with fresh entropy after 2^48 generate calls
rng.reseed()
```

---

## Run the Demo

```bash
# Install dependencies
pip install numpy scipy matplotlib

# Run full demonstration
python demo.py
```

**Output:**
- Full NIST SP 800-22 results for 4 generators
- Security property demonstrations (avalanche, forward secrecy)
- `figure1_output_analysis.png` — byte histogram, bit balance, autocorrelation
- `figure2_nist_comparison.png` — NIST test results comparison table
- `figure3_security_properties.png` — avalanche effect & output independence

---

## References

- NIST SP 800-90A Rev 1 — *Recommendation for Random Number Generation Using Deterministic Random Bit Generators* (2015)
- NIST SP 800-22 Rev 1a — *A Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications* (2010)
- NIST SP 800-57 Part 1 Rev 5 — *Recommendation for Key Management* (security strength table)
