# rsa_utils.py
import random
import math
from dataclasses import dataclass
from typing import Tuple, Optional

# ---- Simple RSA utilities for DEMO ONLY (tiny keys, no padding) ----

def _is_probable_prime(n: int, k: int = 8) -> bool:
    """Miller–Rabin primality test (probabilistic)."""
    if n < 2:
        return False
    # small primes quick check
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # test rounds
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _gen_prime(bits: int) -> int:
    """Generate an odd prime with ~bits bits."""
    assert bits >= 8
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1  # ensure odd & correct bit length
        if _is_probable_prime(n):
            return n

def egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, y, x = egcd(b, a % b)
    return g, x, y - (a // b) * x

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

@dataclass
class RSAKeys:
    n: int
    e: int
    d: int
    p: int
    q: int

def generate_keys(bits_per_prime: int = 16, e: int = 65537) -> RSAKeys:
    """
    Generate a tiny RSA keypair for demo.
    bits_per_prime=16 => n ~ 32 bits (easy to factor for the demo).
    """
    while True:
        p = _gen_prime(bits_per_prime)
        q = _gen_prime(bits_per_prime)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        n = p * q
        d = modinv(e, phi)
        return RSAKeys(n=n, e=e, d=d, p=p, q=q)

def encode_msg_to_int(msg: str) -> int:
    data = msg.encode("utf-8")
    return int.from_bytes(data, "big")

def decode_int_to_msg(m: int) -> str:
    length = (m.bit_length() + 7) // 8
    data = m.to_bytes(length, "big")
    return data.decode("utf-8", errors="replace")

def rsa_encrypt(m: int, n: int, e: int) -> int:
    if m <= 1 or m >= n:
        raise ValueError("Message integer must satisfy 1 < m < n (toy demo)")
    return pow(m, e, n)

def rsa_decrypt(c: int, n: int, d: int) -> int:
    return pow(c, d, n)

def factor_n_trial(n: int) -> Tuple[Optional[int], Optional[int]]:
    """
    Naive trial-division factorization to simulate Eve for small n (~32–40 bits).
    Returns (p, q) if a factorization is found; otherwise (None, None).
    """
    r = int(math.isqrt(n))
    if n % 2 == 0:
        return 2, n // 2
    f = 3
    while f <= r:
        if n % f == 0:
            return f, n // f
        f += 2
    return None, None
