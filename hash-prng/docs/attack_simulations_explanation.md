# `attack_simulations.py` — Hash_DRBG Attack Suite Explained

> **File**: `attacks/attack_simulations.py`  
> **Target**: NIST SP 800-90A Hash_DRBG (SHA-256)  
> **Attacks simulated**: 6 total — 2 succeed (deployment failures), 4 defeated (algorithmic strength)

---

## Purpose

This module **stress-tests** the Hash_DRBG implementation by simulating six classical cryptographic attacks. The goal is not to "break" the DRBG — it is to demonstrate, through concrete code, **which threat models** the standard defends against and **where the real risks lie** (hint: they are in deployment, not in the math).

Each attack function returns a results dictionary indicating whether the attack succeeded, and prints a detailed colored terminal trace showing exactly what happened.

---

## Quick Summary Table

| # | Attack | Result | Root Cause |
|---|--------|--------|------------|
| 1 | State Compromise | ✖ **SUCCEEDS** | Attacker literally has the internal state |
| 2 | Weak Entropy | ✖ **SUCCEEDS** | Only 16-bit seed — brute-forced in seconds |
| 3 | Output Prediction | ✔ **DEFENDED** | SHA-256 preimage resistance (one-way) |
| 4 | Backtracking | ✔ **DEFENDED** | State update is irreversible |
| 5 | Birthday Collision | ✔ **DEFENDED** | 256-bit output → collision at 2^128 blocks |
| 6 | Reseed Exhaustion | ✔ **DEFENDED** | Statistical quality holds after 10,000 calls |

> **Key takeaway**: Attacks 1 and 2 are **deployment/implementation failures** — they succeed because the DRBG was used incorrectly (leaked state, weak entropy), not because the algorithm is flawed. Attacks 3–6 target the algorithm itself and are all defeated.

---

## Attack 1: State Compromise / State Recovery

### Threat Model

An attacker exfiltrates the DRBG's internal state `(V, C, reseed_counter)` at time `T`. They then replay from that stolen state to reproduce every future output.

### How the Simulation Works

```
1.  Create a Hash_DRBG instance and generate 3 "pre-compromise" outputs.
2.  Snapshot the internal state (V, C, reseed_counter).
3.  The legitimate user generates 3 more outputs.
4.  The attacker creates a clone DRBG, loads the stolen state, and generates 3 outputs.
5.  Compare: attacker's outputs === legitimate outputs.
```

### Result: ✖ SUCCEEDS

The attacker **perfectly reproduces** all 3 post-compromise outputs. This is expected — the DRBG is deterministic, so identical state → identical output.

### What It Cannot Do

The attacker **cannot recover the 3 pre-compromise outputs**. The state update rule:

```
V_new = (V + Hash(0x03 || V) + C + counter) mod 2^440
```

is a **one-way function**. Reversing it requires a SHA-256 preimage attack — computationally infeasible. This property (backtracking resistance) is formally tested in Attack 4.

### Mitigation

- Protect the DRBG state like a cryptographic key.
- **Reseed frequently** — each reseed mixes fresh OS entropy, making old stolen state useless.
- Use memory protection (mlock, guard pages) to prevent state leakage.

---

## Attack 2: Weak / Known-Entropy Attack

### Threat Model

The entropy source is compromised or defective. Instead of 256+ bits of genuine entropy, the DRBG is seeded with only **16 bits** of randomness (e.g., a timestamp modulo 65,536).

### How the Simulation Works

```
1.  Victim instantiates the DRBG with a 2-byte seed (only 65,536 possibilities).
2.  Victim generates 32 bytes of output.
3.  Attacker brute-forces all 65,536 possible seeds:
      for candidate in range(0, 2^16):
          create DRBG with candidate as seed
          if generate(32) == victim's output:
              CRACKED — all future outputs are predictable.
```

### Result: ✖ SUCCEEDS

The attacker finds the correct seed in under a second. From this point, they can predict **every future output** the victim will ever produce.

### Why This Matters

The DRBG algorithm itself is perfectly sound — the weakness is entirely in the **entropy input**. NIST SP 800-90A requires:

| Parameter | NIST Minimum | Attack Simulation |
|-----------|-------------|-------------------|
| Entropy bits | ≥ `security_strength` (128 for SHA-256) | **16 bits** ← fatal |
| Nonce | ≥ `security_strength / 2` (64 bits) | All zeros ← fatal |

With genuine 128-bit entropy, brute-force would require ~2^128 ≈ 3.4 × 10^38 attempts — millions of years even at 10^15 guesses per second.

### Mitigation

- **Always use `os.urandom()`** for entropy and nonce — it draws from the OS's CSPRNG.
- Never use time-based seeds, PIDs, or user input as the sole entropy source.
- The default `HashDRBG.__init__()` does this correctly.

---

## Attack 3: Output-Only Prediction (Black-Box)

### Threat Model

The attacker can observe N DRBG output blocks but has **no access to the internal state**. They attempt to predict the (N+1)th output.

### How the Simulation Works

```
1.  DRBG generates 8 consecutive 32-byte output blocks (attacker observes all of them).
2.  DRBG generates the 9th block (the "target" — attacker must predict this).
3.  Attacker's best strategy: random guess (since they cannot invert SHA-256).
4.  Compare attacker's guess vs. real output.
```

The simulation also tries XOR-combining observed outputs to check for structural leakage — none is found.

### Result: ✔ DEFENDED

The attacker's guess has a **1/2^256 ≈ 8.6 × 10^-78** probability of matching. This is computationally indistinguishable from zero.

### Why It Fails

Each output block is produced by `Hashgen(V)`, which iteratively hashes `V, V+1, V+2, ...` After output is produced, `V` is updated:

```
H = Hash(0x03 || V)
V_new = (V + H + C + counter) mod 2^440
```

To predict the next output, the attacker would need `V_new`, which requires knowing `V` — but `V` was never revealed, and recovering it from the output means **inverting SHA-256** (breaking preimage resistance).

### Security Property: Prediction Resistance

> The output sequence of Hash_DRBG is computationally indistinguishable from a truly random sequence, assuming SHA-256 is a secure hash function.

---

## Attack 4: Backtracking Attack (Recovering Past Outputs)

### Threat Model

The attacker compromises the **current** state `(V_now, C)` and attempts to **reverse** the state update to find `V_prev` — thereby recovering past outputs.

### How the Simulation Works

```
1.  DRBG generates 5 outputs (past outputs the attacker wants to recover).
2.  Attacker captures V_now, C, and reseed_counter.
3.  Attacker needs to solve:
        V_now = (V_prev + Hash(0x03 || V_prev) + C + (ctr-1)) mod 2^440
    for V_prev.
4.  Rearranged:
        V_prev + Hash(0x03 || V_prev) = V_now - C - (ctr-1)  mod 2^440
5.  Attacker tries 50,000 random candidates for V_prev.
```

### Result: ✔ DEFENDED

No candidate matches. The search space is 2^440 ≈ 2.8 × 10^132 — even trying 50,000 candidates covers an astronomically negligible fraction.

### Why It Fails

The equation `V_prev + Hash(0x03 || V_prev) = target` is a **fixed-point problem** involving SHA-256. There is no shortcut — the attacker must:

1. Guess `V_prev`.
2. Compute `Hash(0x03 || V_prev)`.
3. Check if `V_prev + Hash(...)` matches the target.

This is equivalent to a **preimage attack** on SHA-256, which has complexity 2^256 (or 2^440 for the full state space).

### Security Property: Backtracking Resistance

> Compromising the current DRBG state reveals nothing about past outputs. The state-update function is a one-way compression — past states are permanently destroyed.

---

## Attack 5: Birthday / Output Collision

### Threat Model

The attacker collects a massive number of output blocks and looks for **collisions** (two identical blocks). If collisions occur at a rate significantly above the birthday bound, it would indicate a weakness in the DRBG's output distribution.

### How the Simulation Works

```
1.  Generate 100,000 consecutive 32-byte (256-bit) output blocks.
2.  Store each block in a set and check for duplicates.
3.  Calculate the theoretical collision probability:
        P ≈ N² / (2 × 2^256)
```

### Result: ✔ DEFENDED

**Zero collisions** in 100,000 blocks.

### The Mathematics

For `N` outputs from a 256-bit space, the Birthday Paradox predicts the first collision at approximately:

```
N ≈ √(2^256) = 2^128 ≈ 3.4 × 10^38
```

The simulation generates N = 100,000 = 10^5 blocks, which is 10^33 times fewer than needed.

| Metric | Value |
|--------|-------|
| Blocks generated | 100,000 |
| Blocks needed for 50% collision probability | ~2^128 ≈ 3.4 × 10^38 |
| Theoretical collision probability at N=10^5 | ≈ 4.3 × 10^-68 |
| Actual collisions found | **0** |

### Security Implication

An attacker cannot use output collisions as a distinguishing attack. The output space is large enough that collisions are practically impossible in any realistic scenario.

---

## Attack 6: Reseed Exhaustion

### Threat Model

The attacker prevents the application from ever calling `reseed()` — for example, by blocking access to `/dev/urandom`. Does the DRBG's output quality degrade over time, allowing statistical attacks?

### How the Simulation Works

```
1.  Instantiate a fresh DRBG and generate 1,000 bytes (early output).
2.  Call generate() 10,000 times without any reseed.
3.  Generate another 1,000 bytes (late output).
4.  Run NIST Monobit (Frequency) test on both early and late output.
5.  Compare bit proportions — should both be ≈ 0.5.
```

### Result: ✔ DEFENDED

Both early and late outputs pass the Monobit test with p-values well above the 0.01 threshold. Bit proportions remain close to 0.5.

### Why It Holds

The state update after every `generate()` call:

```
H = Hash(0x03 || V)
V_new = (V + H + C + counter) mod 2^440
```

acts as a **cryptographic re-keying** operation. Each new `V` is derived through SHA-256, which thoroughly mixes the bits. The counter ensures every update is unique even if `V` were somehow repeated.

NIST allows up to **2^48 generate calls** without reseeding before the `ReseedRequiredError` is raised. This limit is conservative — the hash-based state update provides security equivalent to a fresh instantiation.

---

## Architecture of the Simulation Code

### Helper Functions

| Function | Purpose |
|----------|---------|
| `_header(n, title)` | Prints a styled box header for each attack |
| `_info(msg)` | Prints dimmed informational text |
| `_result(ok, label, detail)` | Prints ✔ DEFENDED or ✖ SUCCEEDS with explanation |
| `_snapshot_state(drbg)` | Deep-copies `(V, C, reseed_counter, algorithm)` |
| `_restore_state(drbg, snap)` | Overwrites a DRBG's state with a snapshot |

### Creating an "Attacker's DRBG"

Several attacks need to create a DRBG without going through the normal `__init__` (which auto-generates entropy). The pattern used is:

```python
attacker_drbg = HashDRBG.__new__(HashDRBG)          # skip __init__
attacker_drbg.algorithm = HashAlgorithm.SHA256       # copy configuration
attacker_drbg._params   = {...}                      # copy parameters
attacker_drbg._state    = None
attacker_drbg._instantiate(controlled_entropy, ...)  # use attacker-controlled seed
```

This bypasses the OS entropy injection to simulate worst-case scenarios.

---

## Summary of Security Properties Tested

```
┌─────────────────────────────────────────────────────────────────┐
│                  Hash_DRBG Security Map                         │
├─────────────────────────┬───────────────────────────────────────┤
│ Forward Secrecy         │ Attack 1 shows: state → future       │
│ (Prediction Resistance) │ outputs. But reseed breaks the chain. │
├─────────────────────────┼───────────────────────────────────────┤
│ Backtracking Resistance │ Attack 4 proves: current state ↛     │
│                         │ past outputs. SHA-256 is one-way.     │
├─────────────────────────┼───────────────────────────────────────┤
│ Output Indistinguish-   │ Attack 3 shows: output is             │
│ ability                 │ indistinguishable from random.         │
├─────────────────────────┼───────────────────────────────────────┤
│ Collision Resistance    │ Attack 5 shows: no collisions in      │
│                         │ 100K blocks (need 2^128 for 50%).     │
├─────────────────────────┼───────────────────────────────────────┤
│ Long-Run Stability      │ Attack 6 shows: no degradation        │
│                         │ after 10,000 calls without reseed.     │
├─────────────────────────┼───────────────────────────────────────┤
│ Entropy Dependency      │ Attack 2 shows: weak entropy ⇒        │
│                         │ total break. Use os.urandom()!         │
└─────────────────────────┴───────────────────────────────────────┘
```

---

## Key Lessons

1. **The algorithm is not the weak link.** Attacks 3–6 all fail against Hash_DRBG. The cryptographic foundations (SHA-256 preimage resistance, birthday bound, state update mixing) are solid.

2. **Deployment is the weak link.** Attacks 1 and 2 both succeed — because the DRBG was misused:
   - Attack 1: The state was leaked (memory dump, side channel).
   - Attack 2: The entropy was weak (16-bit seed instead of 128+ bits).

3. **Reseed is a safety net, not a requirement.** The DRBG maintains cryptographic quality without reseeding (Attack 6), but reseeding after a suspected compromise destroys the attacker's advantage (Attack 1 mitigation).

4. **The state update is the core defense.** The function `V_new = (V + Hash(0x03||V) + C + ctr) mod 2^440` appears in every attack analysis. It provides:
   - **Forward secrecy**: future outputs change unpredictably.
   - **Backtracking resistance**: past states are destroyed.
   - **Mixing**: every bit of the new state depends on every bit of the old state (via SHA-256 avalanche).
