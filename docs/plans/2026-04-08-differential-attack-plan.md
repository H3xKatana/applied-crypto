# Differential Cryptanalysis Attack Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement differential cryptanalysis attack on toy cipher and DES, with beautiful visualizations

**Architecture:** Two-tier approach - start with custom toy cipher for learning fundamentals, then apply to real DES

**Tech Stack:** Python, NumPy, Matplotlib for visualizations

---

### Task 1: Create project structure and toy cipher

**Files:**
- Create: `differential-attack/toy_cipher.py`
- Create: `differential-attack/des.py`
- Create: `differential-attack/README.md`

**Step 1: Create directory and toy cipher**

```python
import numpy as np

class ToyCipher:
    """
    Simplified toy cipher for learning differential cryptanalysis.
    8-bit block, 10-bit key, 2 rounds
    """
    
    def __init__(self, key):
        self.key = key
        self.S1 = self._create_sbox()
        self.S2 = self._create_sbox()
    
    def _create_sbox(self):
        sbox = list(range(16))
        np.random.seed(42)
        np.random.shuffle(sbox)
        return sbox
    
    def f(self, right, round_key):
        """Feistel function"""
        combined = (right ^ round_key) & 0x0F
        left = (self.S1[combined >> 2] << 2) | (self.S2[combined & 0x03])
        return left ^ right
    
    def encrypt(self, plaintext):
        L, R = (plaintext >> 4) & 0x0F, plaintext & 0x0F
        K1, K2 = (self.key >> 5) & 0x1F, self.key & 0x1F
        
        L = L ^ self.f(R, K1)
        R = R ^ self.f(L, K1)
        
        L = L ^ self.f(R, K2)
        R = R ^ self.f(L, K2)
        
        return (L << 4) | R
```

**Step 2: Create DES implementation (simplified)**

```python
class SimplifiedDES:
    """DES-like cipher for differential attack demo"""
    # ... IP, expansion, S-boxes, P-box implementation
```

**Step 3: Commit**

```bash
git add differential-attack/
git commit -m "feat: add toy cipher and DES implementations"
```

---

### Task 2: Differential pair generator

**Files:**
- Create: `differential-attack/pairs.py`
- Modify: `differential-attack/README.md`

**Step 1: Write pair generator**

```python
def generate_differential_pairs(cipher, num_pairs=100):
    """Generate plaintext pairs with controlled XOR difference"""
    pairs = []
    delta = 0x80  # High probability difference for toy cipher
    
    for _ in range(num_pairs):
        p = np.random.randint(0, 256)
        p_prime = p ^ delta
        c = cipher.encrypt(p)
        c_prime = cipher.encrypt(p_prime)
        pairs.append((p, p_prime, c, c_prime))
    
    return pairs
```

**Step 2: Test and commit**

---

### Task 3: Differential attack implementation

**Files:**
- Create: `differential-attack/attack.py`

**Step 1: Implement attack**

```python
def differential_attack(cipher, pairs, key_hint=None):
    """
    Recover key using differential cryptanalysis.
    For each candidate subkey, count how many pairs 
    produce expected output difference.
    """
    best_key = None
    best_count = 0
    
    # Test all possible subkeys
    for subkey in range(32):  # 5-bit subkey
        count = 0
        for p, p_prime, c, c_prime in pairs:
            # Analyze differential behavior
            if check_differential_consistency(p, p_prime, c, c_prime, subkey):
                count += 1
        
        if count > best_count:
            best_count = count
            best_key = subkey
    
    return best_key
```

**Step 2: Test and commit**

---

### Task 4: Visualizations

**Files:**
- Create: `differential-attack/visualize.py`

**Step 1: Create visualization script**

```python
import matplotlib.pyplot as plt
import numpy as np

def plot_differential_distribution(pairs):
    """Show how differences propagate through cipher"""
    plt.figure(figsize=(10, 6))
    # Plot histogram of output differences
    differences = [c ^ c_prime for _, _, c, c_prime in pairs]
    plt.hist(differences, bins=32)
    plt.title("Differential Distribution")
    plt.savefig("differential-dist.png")

def plot_attack_success():
    """Visualize attack success rate vs number of pairs"""
    plt.figure(figsize=(10, 6))
    # Plot success rate curve
    plt.plot(num_pairs_list, success_rates)
    plt.xlabel("Number of Plaintext Pairs")
    plt.ylabel("Success Rate")
    plt.title("Attack Effectiveness")
    plt.savefig("attack-success.png")
```

**Step 2: Generate and commit**

---

### Task 5: Update README with full documentation

**Files:**
- Modify: `differential-attack/README.md`

**Step 1: Write comprehensive README**

```markdown
# Differential Cryptanalysis Attack

A comprehensive implementation demonstrating differential cryptanalysis on:
1. Custom toy cipher (educational)
2. DES (real-world)

## Quick Start

```bash
cd differential-attack
python visualize.py
```

## What is Differential Cryptanalysis?

Differential cryptanalysis is a chosen-plaintext attack that exploits:
- Pairs of plaintexts with known XOR differences
- Probability that this difference propagates through rounds
- Statistical correlation between input/output differences

## Visualizations

Generated by `visualize.py`:
- `differential-dist.png` - Distribution of output differences
- `attack-success.png` - Success rate vs pairs used
- `characteristic.png` - Differential characteristic visualization
```

**Step 2: Generate all visualizations**

```bash
cd differential-attack
python visualize.py
```

Expected output: PNG files generated

**Step 3: Commit**

---

## Plan Complete

**Execution choice:**
1. **Subagent-Driven** - Fresh subagent per task, review between
2. **Parallel Session** - New session with executing-plans

Which approach?
