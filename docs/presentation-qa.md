# Differential Cryptanalysis - Presentation Q&A

## Common Questions & Answers

### Q: Why use ΔP = 0x80 (or 0x40) as differential?

**Answer:**
- `0x80` flips only the MSB (most significant bit)
- In a Feistel cipher, this creates **predictable propagation**
- The difference affects only ONE half initially (right half = 0x00)
- High probability: ~50-100% for correct key vs random (~1%) for wrong keys
- It's the **path of least resistance** through the rounds

### Q: How many pairs are needed?

| Cipher | Pairs | Success Rate |
|--------|-------|--------------|
| DemoCipher | 10 | ~70% |
| DemoCipher | 20+ | 100% |
| SimplifiedDES | 30+ | Reliable |

**Trade-off:** More pairs = more confident but slower

### Q: How does this compare to brute force?

- **Brute force:** Try ALL keys (1024 for DemoCipher)
- **Differential:** Uses statistical filtering - same complexity but smarter
- For small keys, brute force is actually **faster**!
- The value is in understanding the **principle** for real ciphers

### Q: What makes a cipher vulnerable?

- Few rounds (ours have only 2)
- Small S-boxes (4-bit vs DES's 6-bit)
- Predictable key schedule
- Poor diffusion properties
- Linear/probable differentials exist

### Q: Is this attack practical for real ciphers?

- **DES:** Yes! Biham & Shamir (1991) - 2^47 chosen plaintexts needed
- **AES:** Designed to resist - more rounds, better diffusion
- Our versions demonstrate the **principle** without real-world damage

### Q: Real DES complexity numbers?

| Metric | Value |
|--------|-------|
| DES Key Space | 2^56 (72 quadrillion) |
| Differential Attack | 2^47 operations |
| Improvement | 512x faster than brute force |

### Q: Why multiple keys can work (equivalent keys)?

- The S-boxes in our cipher are **not bijective** (not perfect mappings)
- Different keys can produce the **same encryption function**
- Both 0x3FF and 0x1EF give identical ciphertexts for all inputs
- This is a weakness in simplified design

---

## Running the Demo

```bash
cd differential-attack
python3 showcase.py
```

The showcase demonstrates:
1. Step-by-step attack on DemoCipher
2. Complexity comparison between ciphers
3. All Q&A answers printed out

## Key Metrics for Presentation

| Cipher | Key Size | Key Space | Attack Time |
|--------|----------|-----------|-------------|
| DemoCipher | 10 bits | 1,024 | <1s |
| SimplifiedDES | 16 bits | 65,536 | ~5s |
| Real DES | 56 bits | 2^56 | 2^47 operations |

## References

- Biham, E., & Shamir, A. (1991). "Differential Cryptanalysis of DES-like Cryptosystems"
- Schneier, B. "Applied Cryptography" - Chapter 12