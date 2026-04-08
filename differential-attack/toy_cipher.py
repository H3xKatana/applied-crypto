import numpy as np


class ToyCipher:
    """
    Simplified toy cipher for learning differential cryptanalysis.
    8-bit block, 10-bit key, 2 rounds with Feistel structure
    """

    def __init__(self, key):
        if key >= 2**10:
            raise ValueError("Key must be 10 bits (0-1023)")
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
        return (left ^ right) & 0x0F

    def encrypt(self, plaintext):
        """Encrypt a single 8-bit plaintext block using standard Feistel"""
        if plaintext >= 2**8:
            raise ValueError("Plaintext must be 8 bits (0-255)")

        L, R = (plaintext >> 4) & 0x0F, plaintext & 0x0F
        K1, K2 = (self.key >> 5) & 0x1F, self.key & 0x1F

        # Round 1: standard Feistel structure
        temp = L
        L = (R ^ self.f(L, K1)) & 0x0F
        R = temp

        # Round 2: standard Feistel structure
        temp = L
        L = (R ^ self.f(L, K2)) & 0x0F
        R = temp

        return ((L << 4) | R) & 0xFF

    def decrypt(self, ciphertext):
        """Decrypt a single 8-bit ciphertext block"""
        if ciphertext >= 2**8:
            raise ValueError("Ciphertext must be 8 bits (0-255)")

        L, R = (ciphertext >> 4) & 0x0F, ciphertext & 0x0F
        K1, K2 = (self.key >> 5) & 0x1F, self.key & 0x1F

        # Reverse Round 2
        temp = R
        R = (L ^ self.f(R, K2)) & 0x0F
        L = temp

        # Reverse Round 1
        temp = R
        R = (L ^ self.f(R, K1)) & 0x0F
        L = temp

        return ((L << 4) | R) & 0xFF


def test_toy_cipher():
    """Test encryption/decryption round-trip"""
    key = 0x3FF  # 10-bit key
    cipher = ToyCipher(key)

    test_plaintexts = [0x00, 0xFF, 0xAB, 0x12, 0xC7, 0x5A, 0x3E]

    print("Toy Cipher Test")
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
    test_toy_cipher()
