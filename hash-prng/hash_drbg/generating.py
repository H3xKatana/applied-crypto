"""
Hash_DRBG — Pseudo-Random Number Generation Demo
==================================================
Demonstrates all core operations of the NIST SP 800-90A Hash_DRBG:
  • Instantiation with OS entropy
  • Generating pseudo-random bytes (various sizes)
  • Additional input mixing
  • Reseeding with fresh entropy
  • Multiple algorithm support (SHA-256, SHA-512, SHA-3-256, SHA-3-512)
  • Uniqueness verification across independent instances
"""

from core import HashDRBG, HashAlgorithm

# ── ANSI styling ──────────────────────────────────────────────────────────────
_BOLD   = "\033[1m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_DIM    = "\033[2m"
_RESET  = "\033[0m"

def _banner(title: str) -> None:
    bar = "═" * 64
    print(f"\n{_BOLD}{_CYAN}╔{bar}╗")
    print(f"║  {title:<63}║")
    print(f"╚{bar}╝{_RESET}")

def _section(n: int, title: str) -> None:
    print(f"\n{_BOLD}{_YELLOW}  [{n}] {title}{_RESET}")
    print(f"  {_DIM}{'─' * 58}{_RESET}")

def _show(label: str, data: bytes) -> None:
    print(f"  {_DIM}{label}:{_RESET} {_GREEN}{data.hex()}{_RESET}  ({len(data)} bytes)")


def main():
    _banner("Hash_DRBG — Pseudo-Random Number Generation")
    print(f"  {_DIM}Standard: NIST SP 800-90A Rev 1, Section 10.1.1{_RESET}")

    # ──────────────────────────────────────────────────────────────────────
    # 1. Basic instantiation & generation (SHA-256)
    # ──────────────────────────────────────────────────────────────────────
    _section(1, "Instantiate SHA-256 Hash_DRBG & generate bytes")

    rng = HashDRBG(HashAlgorithm.SHA256)
    print(f"  {rng}")

    out_32 = rng.generate(32)
    _show("32 bytes (256 bits)", out_32)

    out_16 = rng.generate(16)
    _show("16 bytes (128 bits)", out_16)

    out_64 = rng.generate(64)
    _show("64 bytes (512 bits)", out_64)

    # ──────────────────────────────────────────────────────────────────────
    # 2. Generate with additional input (domain separation)
    # ──────────────────────────────────────────────────────────────────────
    _section(2, "Generate with additional input")
    print(f"  {_DIM}Additional input mixes extra context into the state before{_RESET}")
    print(f"  {_DIM}output generation (e.g., session ID, timestamp).{_RESET}")

    ctx_a = b"session-alpha-001"
    ctx_b = b"session-beta-002"

    out_a = rng.generate(32, additional_input=ctx_a)
    out_b = rng.generate(32, additional_input=ctx_b)

    _show(f"with '{ctx_a.decode()}'", out_a)
    _show(f"with '{ctx_b.decode()}'", out_b)

    # ──────────────────────────────────────────────────────────────────────
    # 3. Reseeding — inject fresh OS entropy
    # ──────────────────────────────────────────────────────────────────────
    _section(3, "Reseed with fresh OS entropy")

    print(f"  Reseed counter before : {_YELLOW}{rng.reseed_counter}{_RESET}")
    pre_reseed = rng.generate(16)
    _show("Output BEFORE reseed", pre_reseed)

    rng.reseed()
    print(f"  Reseed counter after  : {_YELLOW}{rng.reseed_counter}{_RESET}")

    post_reseed = rng.generate(16)
    _show("Output AFTER  reseed", post_reseed)

    print(f"\n  {_DIM}Reseeding mixes fresh entropy, resets the counter, and makes")
    print(f"  prior state unrecoverable — even if the old state was compromised.{_RESET}")

    # ──────────────────────────────────────────────────────────────────────
    # 4. All supported algorithms
    # ──────────────────────────────────────────────────────────────────────
    _section(4, "Generate from all supported algorithms")

    for algo in HashAlgorithm:
        drbg = HashDRBG(algo)
        output = drbg.generate(32)
        strength = drbg.security_strength
        print(f"  {_BOLD}{algo.name:<10}{_RESET} "
              f"({strength}-bit security)  →  {_GREEN}{output.hex()}{_RESET}")

    # ──────────────────────────────────────────────────────────────────────
    # 5. Personalization string — domain separation at instantiation
    # ──────────────────────────────────────────────────────────────────────
    _section(5, "Personalization strings produce different streams")

    rng_app1 = HashDRBG(HashAlgorithm.SHA256, personalization_string=b"AppAlpha")
    rng_app2 = HashDRBG(HashAlgorithm.SHA256, personalization_string=b"AppBeta")

    out_app1 = rng_app1.generate(16)
    out_app2 = rng_app2.generate(16)

    _show("personalization = 'AppAlpha'", out_app1)
    _show("personalization = 'AppBeta' ", out_app2)

    match = out_app1 == out_app2
    print(f"  Outputs identical? {_YELLOW}{'Yes ✖' if match else 'No ✔ (as expected)'}{_RESET}")

    # ──────────────────────────────────────────────────────────────────────
    # 6. Uniqueness — independent instances never collide
    # ──────────────────────────────────────────────────────────────────────
    _section(6, "Uniqueness across 10 independent instances")

    outputs = set()
    for i in range(10):
        d = HashDRBG(HashAlgorithm.SHA256)
        out = d.generate(32)
        outputs.add(out.hex())
        print(f"  instance {i}: {_GREEN}{out.hex()[:32]}…{_RESET}")

    print(f"\n  Unique outputs: {_YELLOW}{len(outputs)}/10{_RESET}  "
          f"{'✔ All unique' if len(outputs) == 10 else '✖ Collision detected!'}")

    # ──────────────────────────────────────────────────────────────────────
    # 7. State evolution — consecutive calls produce different outputs
    # ──────────────────────────────────────────────────────────────────────
    _section(7, "State evolution — 5 consecutive generate() calls")

    rng_seq = HashDRBG(HashAlgorithm.SHA256)
    for i in range(5):
        out = rng_seq.generate(16)
        print(f"  call {i+1}:  {_GREEN}{out.hex()}{_RESET}  "
              f"{_DIM}(reseed_counter={rng_seq.reseed_counter}){_RESET}")

    # ──────────────────────────────────────────────────────────────────────
    # Summary
    # ──────────────────────────────────────────────────────────────────────
    _banner("Summary")
    print(f"  {_GREEN}✔{_RESET} Instantiation with OS entropy              — NIST §10.1.1.2")
    print(f"  {_GREEN}✔{_RESET} Pseudo-random byte generation              — NIST §10.1.1.4")
    print(f"  {_GREEN}✔{_RESET} Additional input mixing                    — NIST §10.1.1.4")
    print(f"  {_GREEN}✔{_RESET} Reseeding with fresh entropy               — NIST §10.1.1.3")
    print(f"  {_GREEN}✔{_RESET} All 4 hash algorithms (SHA-256/512/3-256/3-512)")
    print(f"  {_GREEN}✔{_RESET} Personalization string domain separation")
    print(f"  {_GREEN}✔{_RESET} Uniqueness across independent instances")
    print(f"  {_GREEN}✔{_RESET} State evolves after every generate() call")
    print()


if __name__ == "__main__":
    main()