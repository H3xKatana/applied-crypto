import numpy as np


class SimplifiedDES:
    """
    Simplified DES for differential cryptanalysis demo.
    8-bit block, 16-bit key, 2 rounds with Feistel structure.

    Reduced version of DES with:
    - Expansion (E) - 4-bit to 6-bit
    - Two 4x4 S-boxes
    - P-box permutation

    Vulnerable to differential attack for educational purposes.
    """

    E = [1, 2, 3, 4, 3, 4, 1, 2]
    P = [3, 1, 4, 2]

    S1 = [
        [0x3, 0x8, 0xF, 0x1],
        [0xA, 0x6, 0x9, 0xC],
        [0x5, 0xB, 0x0, 0xD],
        [0xE, 0x7, 0x2, 0x4],
    ]

    S2 = [
        [0xF, 0x4, 0xC, 0x1],
        [0x9, 0x6, 0xA, 0x3],
        [0xB, 0x2, 0x0, 0xD],
        [0x8, 0x7, 0xE, 0x5],
    ]

    def __init__(self, key):
        if key >= 2**16:
            raise ValueError("Key must be 16 bits (0-65535)")
        self.key = key
        self._expand_key()

    def _expand_key(self):
        """Generate round keys from main key"""
        self.K1 = (self.key >> 11) & 0x1F
        self.K2 = (self.key >> 6) & 0x1F

    def _expand(self, nibble):
        """Expand 4-bit input to 6-bit output"""
        result = 0
        for i, e in enumerate(self.E):
            if nibble & (1 << (e - 1)):
                result |= 1 << i
        return result

    def _sbox(self, data):
        """Apply S-boxes to 6-bit input"""
        row = ((data >> 3) & 0x02) | (data & 0x01)
        col = (data >> 1) & 0x03

        out1 = self.S1[row][col]
        out2 = self.S2[row][col]

        return (out1 << 2) | out2

    def _pbox(self, data):
        """Apply P-box permutation"""
        result = 0
        for i, p in enumerate(self.P):
            if data & (1 << (p - 1)):
                result |= 1 << i
        return result

    def f(self, right, round_key):
        """Feistel function"""
        expanded = self._expand(right)
        xored = (expanded ^ round_key) & 0x3F
        sboxed = self._sbox(xored)
        permuted = self._pbox(sboxed)
        return permuted & 0x0F

    def encrypt(self, plaintext):
        """Encrypt a single 8-bit plaintext block"""
        if plaintext >= 2**8:
            raise ValueError("Plaintext must be 8 bits (0-255)")

        L, R = (plaintext >> 4) & 0x0F, plaintext & 0x0F

        # Round 1
        temp = L
        L = (R ^ self.f(L, self.K1)) & 0x0F
        R = temp

        # Round 2
        temp = L
        L = (R ^ self.f(L, self.K2)) & 0x0F
        R = temp

        return ((L << 4) | R) & 0xFF

    def decrypt(self, ciphertext):
        """Decrypt a single 8-bit ciphertext block"""
        if ciphertext >= 2**8:
            raise ValueError("Ciphertext must be 8 bits (0-255)")

        L, R = (ciphertext >> 4) & 0x0F, ciphertext & 0x0F

        # Reverse Round 2
        temp = R
        R = (L ^ self.f(R, self.K2)) & 0x0F
        L = temp

        # Reverse Round 1
        temp = R
        R = (L ^ self.f(R, self.K1)) & 0x0F
        L = temp

        return ((L << 4) | R) & 0xFF


def test_simplified_des():
    """Test encryption/decryption round-trip"""
    key = 0xCAFE  # 16-bit key
    cipher = SimplifiedDES(key)

    test_plaintexts = [0x00, 0xFF, 0xAB, 0x12, 0xC7, 0x5A]

    print("Simplified DES Test")
    print("=" * 40)

    all_pass = True
    for pt in test_plaintexts:
        ct = cipher.encrypt(pt)
        decrypted = cipher.decrypt(ct)
        status = "PASS" if decrypted == pt else "FAIL"
        if status == "FAIL":
            all_pass = False
        print(f"PT: 0x{pt:02X} -> CT: 0x{ct:02X} -> PT': 0x{decrypted:02X} [{status}]")

    if all_pass:
        print("\nAll tests passed!")
    else:
        print("\nSome tests failed!")


if __name__ == "__main__":
    test_simplified_des()
