import numpy as np


class DemoCipher:
    """
    Simplified cipher for learning differential cryptanalysis.
    8-bit block, 20-bit key, 4 rounds with Feistel structure.

    Key derivation:
    - Key is 20 bits (2^20 = 1,048,576 possible keys)
    - Derived into 4 round keys: K1, K2, K3, K4 (5 bits each)
    """

    def __init__(self, key):
        if key >= 2**20:
            raise ValueError("Key must be 20 bits (0-1048575)")
        self.key = key
        self.S1 = self._create_sbox(42)
        self.S2 = self._create_sbox(137)

    def _create_sbox(self, seed):
        sbox = list(range(16))
        np.random.seed(seed)
        np.random.shuffle(sbox)
        return sbox

    def f(self, right, round_key):
        """Feistel function"""
        combined = (right ^ round_key) & 0x0F
        left = (self.S1[combined >> 2] << 2) | (self.S2[combined & 0x03])
        return (left ^ right) & 0x0F

    def encrypt(self, plaintext):
        """Encrypt a single 8-bit plaintext block using standard Feistel"""
        if plaintext >= 2**8:
            raise ValueError("Plaintext must be 8 bits (0-255)")

        L, R = (plaintext >> 4) & 0x0F, plaintext & 0x0F

        # Derive round keys from 20-bit master key
        K1 = (self.key >> 15) & 0x1F  # bits 19-15
        K2 = (self.key >> 10) & 0x1F  # bits 14-10
        K3 = (self.key >> 5) & 0x1F  # bits 9-5
        K4 = self.key & 0x1F  # bits 4-0

        # Round 1
        temp = L
        L = (R ^ self.f(L, K1)) & 0x0F
        R = temp

        # Round 2
        temp = L
        L = (R ^ self.f(L, K2)) & 0x0F
        R = temp

        # Round 3
        temp = L
        L = (R ^ self.f(L, K3)) & 0x0F
        R = temp

        # Round 4
        temp = L
        L = (R ^ self.f(L, K4)) & 0x0F
        R = temp

        return ((L << 4) | R) & 0xFF

    def decrypt(self, ciphertext):
        """Decrypt a single 8-bit ciphertext block"""
        if ciphertext >= 2**8:
            raise ValueError("Ciphertext must be 8 bits (0-255)")

        L, R = (ciphertext >> 4) & 0x0F, ciphertext & 0x0F

        # Derive round keys
        K1 = (self.key >> 15) & 0x1F
        K2 = (self.key >> 10) & 0x1F
        K3 = (self.key >> 5) & 0x1F
        K4 = self.key & 0x1F

        # Reverse Round 4
        temp = R
        R = (L ^ self.f(R, K4)) & 0x0F
        L = temp

        # Reverse Round 3
        temp = R
        R = (L ^ self.f(R, K3)) & 0x0F
        L = temp

        # Reverse Round 2
        temp = R
        R = (L ^ self.f(R, K2)) & 0x0F
        L = temp

        # Reverse Round 1
        temp = R
        R = (L ^ self.f(R, K1)) & 0x0F
        L = temp

        return ((L << 4) | R) & 0xFF


def test_demo_cipher():
    """Test encryption/decryption round-trip"""
    key = 0xFFFFF  # 20-bit key
    cipher = DemoCipher(key)

    test_plaintexts = [0x00, 0xFF, 0xAB, 0x12, 0xC7, 0x5A, 0x3E, 0x81]

    print("Demo Cipher Test (20-bit key, 4 rounds)")
    print("=" * 50)

    all_pass = True
    for pt in test_plaintexts:
        ct = cipher.encrypt(pt)
        decrypted = cipher.decrypt(ct)
        status = "PASS" if decrypted == pt else "FAIL"
        if status == "FAIL":
            all_pass = False
        print(f"PT: 0x{pt:02X} -> CT: 0x{ct:02X} -> PT': 0x{decrypted:02X} [{status}]")

    if all_pass:
        print("\n✓ All tests passed!")
    else:
        print("\n✗ Some tests failed!")


if __name__ == "__main__":
    test_demo_cipher()
