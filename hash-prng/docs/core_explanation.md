# `core.py` — Hash_DRBG Implementation Explained

> **Standard**: NIST SP 800-90A Rev 1, Section 10.1.1  
> **File**: `hash_drbg/core.py`  
> **Supported algorithms**: SHA-256, SHA-512, SHA-3-256, SHA-3-512

---

## Overview

`core.py` implements a **Hash-based Deterministic Random Bit Generator (Hash_DRBG)** strictly following the NIST SP 800-90A standard. It provides cryptographically secure pseudo-random bytes using a hash function as its core primitive.

A DRBG is **not** a simple hash of a seed — it maintains an internal **state** that is updated after every output, making it computationally infeasible to:
- Predict future outputs from past outputs.
- Recover past outputs if the current state is known.

---

## Module-Level Constants and Types

### `HashAlgorithm` (Enum)
```python
class HashAlgorithm(Enum):
    SHA256   = "sha256"
    SHA512   = "sha512"
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"
```
Selects which hash function drives the DRBG. The algorithm choice determines the security strength and internal state size.

---

### `_PARAMS` — NIST Table 2 Parameters

| Algorithm  | Output length (outlen) | Seed length (seedlen) | Security Strength |
|------------|------------------------|------------------------|-------------------|
| SHA-256    | 256 bits               | 440 bits               | 128-bit           |
| SHA-512    | 512 bits               | 888 bits               | 256-bit           |
| SHA-3-256  | 256 bits               | 440 bits               | 128-bit           |
| SHA-3-512  | 512 bits               | 888 bits               | 256-bit           |

These values are dictated by NIST SP 800-90A Table 2 and cannot be changed without violating the standard.

---

### `MAX_RESEED_INTERVAL = 2**48`

The maximum number of `generate()` calls before a mandatory **reseed** is required. After `2^48` calls, the `reseed_counter` would exceed this threshold and a `ReseedRequiredError` is raised.

> **Why?** Even though the state update is cryptographically strong, NIST mandates periodic reseeding to inject fresh real-world entropy and bound the total output from a single seed.

---

### `DRBGState` (Dataclass)

```python
@dataclass
class DRBGState:
    V: bytes            # The working value (seedlen bits)
    C: bytes            # The constant (seedlen bits)
    reseed_counter: int # How many generate() calls since last instantiate/reseed
    algorithm: HashAlgorithm
```

This is the complete **internal state** of the DRBG. It holds:

- **`V`** — the primary "value" updated with every `generate()` call.
- **`C`** — a constant derived from `V` at instantiation/reseed time; injected into every state update to bind outputs to a specific seed lineage.
- **`reseed_counter`** — tracks usage since last seeding event.

> **Security note**: Exposing this state to an attacker gives them full prediction capability for all *future* outputs. This is what the state compromise attack in `attack_simulations.py` demonstrates.

---

### `ReseedRequiredError` (Exception)

Raised by `generate()` when `reseed_counter > MAX_RESEED_INTERVAL`. The caller must invoke `reseed()` before generating more bytes.

---

## The `HashDRBG` Class

### Constructor `__init__`

```python
def __init__(
    self,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    personalization_string: bytes = b"",
    prediction_resistance: bool = False,
)
```

**What it does:**
1. Stores algorithm and parameters.
2. Immediately draws entropy from the OS (`os.urandom`) — both a full-length entropy input and a half-length nonce.
3. Calls `_instantiate()` to derive the initial `V` and `C`.

**Parameters:**
| Parameter | Purpose |
|-----------|---------|
| `algorithm` | Selects SHA-256/512/3-256/3-512 |
| `personalization_string` | Optional domain-separation string mixed into the initial seed |
| `prediction_resistance` | Flag for informational purposes (full prediction resistance requires fresh entropy per `generate()` call — not automatically enforced here) |

---

## Private Primitives

### `_H(data)` — The Hash Function

```python
def _H(self, data: bytes) -> bytes:
    return hashlib.new(self.algorithm.value, data).digest()
```

A thin wrapper around Python's `hashlib`. Applies the selected hash function to arbitrary bytes. All other primitives are built on top of `_H`.

---

### `_hash_df(input_string, no_of_bits_to_return)` — Hash Derivation Function

**NIST SP 800-90A Section 10.3.1**

```
temp = ""
for counter in 1 .. ceil(bits / outlen):
    temp += Hash(counter || no_of_bits_to_return || input_string)
return leftmost no_of_bits_to_return bits of temp
```

**Purpose**: Stretches or compresses arbitrary-length input into *exactly* `seedlen` bits in a cryptographically secure way. Used to derive `V` and `C` during instantiation and reseeding.

**Why prefix with a counter?** — Each iteration produces independent hash output blocks, and the counter ensures they differ even with identical input. The `no_of_bits_to_return` field further domain-separates calls requesting different output lengths.

---

### `_hashgen(requested_bits, V)` — The Hashgen Process

**NIST SP 800-90A Section 10.1.1.4 (Hashgen)**

```
m = ceil(requested_bits / outlen)
data = V
result = ""
for _ in range(m):
    result += Hash(data)
    data = (data + 1) mod 2^seedlen
return leftmost requested_bits of result
```

**Purpose**: Generates the actual pseudo-random output by hashing an incrementing version of `V`. Each block of `outlen` bits is produced by a single hash call.

**Key property**: The output is derived from `V` *before* the state update. This means even if an attacker sees the output, they cannot directly derive the *new* `V` (which is computed afterwards with additional mixing).

---

### `_mod_add(*values)` — Modular Addition

```python
def _mod_add(self, *values: bytes) -> bytes:
    total = sum(int.from_bytes(v, "big") for v in values)
    total %= 2 ** self._params["seedlen"]
    return total.to_bytes(self._seedlen_bytes, "big")
```

Adds multiple big-endian byte sequences together modulo `2^seedlen`. Used in the state update step of `generate()` to combine `V`, `H`, `C`, and `reseed_counter` into the new `V`.

---

## Public Operations (NIST-Defined)

### `_instantiate(entropy_input, nonce, personalization_string)` — Section 10.1.1.2

```
seed_material = entropy_input || nonce || personalization_string
seed          = hash_df(seed_material, seedlen)
V             = seed
C             = hash_df(0x00 || V, seedlen)
```

**Derives the initial internal state from:**
- **`entropy_input`**: OS-sourced randomness (`seedlen` bytes).
- **`nonce`**: A half-length additional random value to prevent predictability even if the entropy source is weak.
- **`personalization_string`**: Optional application-specific domain separator.

The prefix byte `0x00` when computing `C` domain-separates it from `V` itself so the two values are cryptographically independent despite being derived from the same seed.

---

### `reseed(additional_input, entropy_input)` — Section 10.1.1.3

```
seed_material = 0x01 || V || entropy_input || additional_input
seed          = hash_df(seed_material, seedlen)
V             = seed
C             = hash_df(0x00 || V, seedlen)
reseed_counter = 1
```

**Purpose**: Mixes fresh OS entropy into the state. Should be called:
- When `reseed_counter` approaches `MAX_RESEED_INTERVAL`.
- After a suspected state compromise (fresh entropy breaks the attacker's prediction chain).

The prefix `0x01` distinguishes the reseed hash_df call from instantiation (`no prefix`) and from the generate additional-input step (`0x02`).

---

### `generate(num_bytes, additional_input)` — Section 10.1.1.4

This is the main output function. Its steps are:

#### Step 1: Check reseed counter
```python
if self._state.reseed_counter > MAX_RESEED_INTERVAL:
    raise ReseedRequiredError(...)
```

#### Step 2: Mix optional additional input
```
if additional_input:
    w = Hash(0x02 || V || additional_input)
    V = (V + w) mod 2^seedlen
```
The `0x02` prefix domain-separates this from other hash calls.

#### Step 3: Generate output
```
returned_bits = hashgen(num_bytes * 8, V)
```
Delegates to `_hashgen()` which produces pseudo-random bytes by iteratively hashing `V, V+1, V+2, ...`

#### Step 4: Update state (forward secrecy)
```
H     = Hash(0x03 || V)
new_V = (V + H + C + reseed_counter) mod 2^seedlen
reseed_counter += 1
```

**Why this update provides forward secrecy:**
- `H` is a one-way function of `V` — output alone cannot reconstruct `V`.
- `C` is mixed in to bind the new state to the original seed.
- `reseed_counter` makes each update unique even for repeated inputs.
- Because the output was generated *before* this update, knowing the output does not reveal `new_V`.

---

## Diagnostic Properties

| Property/Method | Description |
|----------------|-------------|
| `security_strength` | Returns the bit security level (128 or 256) |
| `reseed_counter` | Returns the current generate-call count |
| `__repr__` | Human-readable summary: algorithm, security strength, reseed counter |

---

## Data Flow Diagram

```
OS Entropy + Nonce + Personalization
          │
          ▼
     hash_df()  ──────────────────────────────────┐
          │                                        │
          ▼                                        │
     V (seedlen bits)   ──► hash_df(0x00 || V) ──► C (constant)
          │
          ▼ (each generate() call)
     hashgen(bits, V) ─────────────────────────► OUTPUT (random bytes)
          │
          ▼
     H = Hash(0x03 || V)
     new_V = (V + H + C + counter) mod 2^seedlen
          │
          └──────► (next generate() call uses new_V)
```

---

## Security Properties Implemented

| Property | Mechanism |
|----------|-----------|
| **Forward secrecy** | State update after each generate() makes prior states unrecoverable |
| **Backtracking resistance** | One-way hash update: cannot reverse `new_V → V` |
| **Prediction resistance** | Fresh OS entropy at instantiation; optional via periodic reseeding |
| **Domain separation** | Prefix bytes `0x00–0x03` distinguish each type of hash call |
| **Reseed enforcement** | `MAX_RESEED_INTERVAL` cap forces periodic entropy injection |

---

## Usage Example

```python
from hash_drbg.core import HashDRBG, HashAlgorithm

# Instantiate with SHA-256 (128-bit security)
rng = HashDRBG(HashAlgorithm.SHA256)

# Generate 64 random bytes
output = rng.generate(64)
print(output.hex())

# Generate with additional input (e.g. application context)
output2 = rng.generate(32, additional_input=b"session-id-xyz")

# Reseed with fresh entropy
rng.reseed()
```
