"""
Differential Cryptanalysis Attack Implementation

A educational implementation demonstrating differential cryptanalysis on:
- Custom toy cipher (simplified Feistel cipher for learning fundamentals)
- Simplified DES (reduced version of real DES for attack demonstration)
"""

from differential_attack.demo import DemoCipher
from differential_attack.des import SimplifiedDES

__all__ = ["DemoCipher", "SimplifiedDES"]
