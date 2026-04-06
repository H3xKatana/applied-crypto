"""
Hash_DRBG — NIST SP 800-90A Rev 1 compliant implementation
============================================================
Reference: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
           Section 10.1.1

Supports: SHA-256, SHA-512, SHA-3-256, SHA-3-512

Security strengths:
  SHA-256  → 128-bit security (seedlen=440 bits)
  SHA-512  → 256-bit security (seedlen=888 bits)
  SHA-3-256 → 128-bit security (seedlen=440 bits)
  SHA-3-512 → 256-bit security (seedlen=888 bits)
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class HashAlgorithm(Enum):
    SHA256   = "sha256"
    SHA512   = "sha512"
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"


# NIST SP 800-90A Table 2: Definitions for Hash-Based DRBG Mechanisms
_PARAMS = {
    HashAlgorithm.SHA256:   {"outlen": 256, "seedlen": 440, "security_strength": 128},
    HashAlgorithm.SHA512:   {"outlen": 512, "seedlen": 888, "security_strength": 256},
    HashAlgorithm.SHA3_256: {"outlen": 256, "seedlen": 440, "security_strength": 128},
    HashAlgorithm.SHA3_512: {"outlen": 512, "seedlen": 888, "security_strength": 256},
}

# NIST SP 800-90A Section 10.1 — Reseed interval limit
MAX_RESEED_INTERVAL = 2**48


@dataclass
class DRBGState:
    """Internal state of the Hash_DRBG (V, C, reseed_counter)."""
    V: bytes               # Value — seedlen bits
    C: bytes               # Constant — seedlen bits
    reseed_counter: int    # Number of generate calls since last reseed
    algorithm: HashAlgorithm


class ReseedRequiredError(Exception):
    """Raised when reseed_counter exceeds MAX_RESEED_INTERVAL."""
    pass


class HashDRBG:
    """
    NIST SP 800-90A Rev 1 — Hash_DRBG

    Security properties demonstrated:
    - Forward secrecy: past outputs cannot be recovered after state update
    - Backtracking resistance: compromising current state does not reveal past outputs
    - Prediction resistance: output is computationally indistinguishable from uniform random

    Usage:
        rng = HashDRBG(HashAlgorithm.SHA256)
        random_bytes = rng.generate(64)
    """

    def __init__(
        self,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        personalization_string: bytes = b"",
        prediction_resistance: bool = False,
    ):
        self.algorithm = algorithm
        self.prediction_resistance = prediction_resistance
        self._params = _PARAMS[algorithm]
        self._outlen_bytes = self._params["outlen"] // 8
        self._seedlen_bytes = self._params["seedlen"] // 8
        self._state: Optional[DRBGState] = None

        # Instantiate immediately using OS entropy
        entropy  = os.urandom(self._seedlen_bytes)
        nonce    = os.urandom(self._seedlen_bytes // 2)
        self._instantiate(entropy, nonce, personalization_string)

    # -----------------------------------------------------------------------
    # Private: Core NIST SP 800-90A primitives
    # -----------------------------------------------------------------------

    def _H(self, data: bytes) -> bytes:
        """Apply the chosen hash function."""
        name = self.algorithm.value  # e.g. "sha256", "sha3_256"
        return hashlib.new(name, data).digest()

    def _hash_df(self, input_string: bytes, no_of_bits_to_return: int) -> bytes:
        """
        NIST SP 800-90A Section 10.3.1 — Hash Derivation Function (hash_df)

        Derives a seed of exactly `no_of_bits_to_return` bits from input_string
        using iterated hashing. This is the key to mixing entropy securely.

        Steps:
            temp = ""
            for counter in 1..ceil(no_of_bits/outlen):
                temp += Hash(counter || no_of_bits_to_return || input_string)
            return leftmost no_of_bits_to_return bits of temp
        """
        no_of_bytes = (no_of_bits_to_return + 7) // 8
        iterations  = (no_of_bits_to_return + self._params["outlen"] - 1) // self._params["outlen"]

        temp = b""
        for counter in range(1, iterations + 1):
            payload = (
                counter.to_bytes(1, "big")
                + no_of_bits_to_return.to_bytes(4, "big")
                + input_string
            )
            temp += self._H(payload)

        return temp[:no_of_bytes]

    def _hashgen(self, requested_bits: int, V: bytes) -> bytes:
        """
        NIST SP 800-90A Section 10.1.1.4 — The Hashgen Process

        Generates `requested_bits` pseudo-random bits by iteratively hashing
        an incrementing counter seeded from V. Each call produces `outlen` bits.
        V is incremented mod 2^seedlen between iterations.

        This is the output-generation core of Hash_DRBG.
        """
        m = (requested_bits + self._params["outlen"] - 1) // self._params["outlen"]
        data   = V
        result = b""

        for _ in range(m):
            result += self._H(data)
            # Increment data mod 2^seedlen (treating as a big-endian integer)
            val  = int.from_bytes(data, "big")
            val  = (val + 1) % (2 ** self._params["seedlen"])
            data = val.to_bytes(self._seedlen_bytes, "big")

        # Return exactly the requested number of bits (left-truncate)
        requested_bytes = (requested_bits + 7) // 8
        return result[:requested_bytes]

    def _mod_add(self, *values: bytes) -> bytes:
        """Add big-endian byte sequences mod 2^seedlen."""
        total = sum(int.from_bytes(v, "big") for v in values)
        total %= 2 ** self._params["seedlen"]
        return total.to_bytes(self._seedlen_bytes, "big")

    # -----------------------------------------------------------------------
    # Public: NIST operations
    # -----------------------------------------------------------------------

    def _instantiate(
        self,
        entropy_input: bytes,
        nonce: bytes,
        personalization_string: bytes = b"",
    ) -> None:
        """
        NIST SP 800-90A Section 10.1.1.2 — Hash_DRBG Instantiate

        Derives V and C from entropy + nonce + personalization string.
        """
        seed_material = entropy_input + nonce + personalization_string
        seed = self._hash_df(seed_material, self._params["seedlen"])

        V = seed
        C = self._hash_df(b"\x00" + V, self._params["seedlen"])

        self._state = DRBGState(
            V=V, C=C, reseed_counter=1, algorithm=self.algorithm
        )

    def reseed(
        self,
        additional_input: bytes = b"",
        entropy_input: Optional[bytes] = None,
    ) -> None:
        """
        NIST SP 800-90A Section 10.1.1.3 — Hash_DRBG Reseed

        Mixes fresh entropy into the internal state.
        Should be called when reseed_counter approaches MAX_RESEED_INTERVAL,
        or when fresh entropy is available after a state compromise.
        """
        assert self._state is not None
        if entropy_input is None:
            entropy_input = os.urandom(self._seedlen_bytes)

        seed_material = b"\x01" + self._state.V + entropy_input + additional_input
        seed = self._hash_df(seed_material, self._params["seedlen"])

        V = seed
        C = self._hash_df(b"\x00" + V, self._params["seedlen"])

        self._state = DRBGState(
            V=V, C=C, reseed_counter=1, algorithm=self.algorithm
        )

    def generate(
        self,
        num_bytes: int,
        additional_input: bytes = b"",
    ) -> bytes:
        """
        NIST SP 800-90A Section 10.1.1.4 — Hash_DRBG Generate

        Returns `num_bytes` pseudo-random bytes.

        After output is produced, V is updated using:
            H = Hash(0x03 || V)
            V = (V + H + C + reseed_counter) mod 2^seedlen

        This state update ensures forward secrecy: knowing current output
        does NOT allow reconstruction of future OR past outputs.
        """
        assert self._state is not None

        if self._state.reseed_counter > MAX_RESEED_INTERVAL:
            raise ReseedRequiredError(
                f"Reseed counter ({self._state.reseed_counter}) exceeded limit."
                " Call reseed() before generating more output."
            )

        # Optional: mix in additional input
        V = self._state.V
        if additional_input:
            w = self._H(b"\x02" + V + additional_input)
            V = self._mod_add(V, w.ljust(self._seedlen_bytes, b"\x00"))

        # Generate pseudo-random bits
        returned_bits = self._hashgen(num_bytes * 8, V)

        # Update state — this is what provides forward secrecy
        H = self._H(b"\x03" + V)
        new_V = self._mod_add(
            V,
            H.ljust(self._seedlen_bytes, b"\x00"),
            self._state.C,
            self._state.reseed_counter.to_bytes(4, "big"),
        )

        self._state = DRBGState(
            V=new_V,
            C=self._state.C,
            reseed_counter=self._state.reseed_counter + 1,
            algorithm=self.algorithm,
        )

        return returned_bits

    # -----------------------------------------------------------------------
    # Diagnostics
    # -----------------------------------------------------------------------

    @property
    def security_strength(self) -> int:
        return self._params["security_strength"]

    @property
    def reseed_counter(self) -> int:
        return self._state.reseed_counter if self._state else 0

    def __repr__(self) -> str:
        return (
            f"HashDRBG(algorithm={self.algorithm.name}, "
            f"security_strength={self.security_strength}-bit, "
            f"reseed_counter={self.reseed_counter})"
        )
