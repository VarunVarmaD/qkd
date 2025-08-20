\
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict
import numpy as np
import secrets

# Bases: 0 = Z (rectilinear), 1 = X (diagonal)

@dataclass
class BB84Result:
    n_qubits: int
    noise: float
    eve_present: bool
    sample_rate: float
    threshold: float
    seed: Optional[int]

    alice_bits: np.ndarray
    alice_bases: np.ndarray
    bob_bases: np.ndarray
    bob_bits: np.ndarray
    eve_bases: Optional[np.ndarray]

    sift_mask: np.ndarray
    sifted_alice: np.ndarray
    sifted_bob: np.ndarray

    qber_full: float
    sample_indices: np.ndarray
    qber_sample: float
    aborted: bool
    reason: str
    final_key: np.ndarray  # post-sample key (if not aborted)

def _rng(seed: Optional[int]) -> np.random.Generator:
    if seed is None:
        # derive a seed from system entropy for reproducibility per run
        seed = int.from_bytes(secrets.token_bytes(8), "big")
    return np.random.default_rng(seed)

def _random_bits(rng: np.random.Generator, n: int) -> np.ndarray:
    return rng.integers(0, 2, size=n, dtype=np.int8)

def _measure_with_basis(true_bit: int, prepared_basis: int, measure_basis: int, rng: np.random.Generator) -> int:
    """
    Simulate measurement of a single qubit encoded with (true_bit, prepared_basis)
    and measured in measure_basis.
    - If bases match: return true_bit
    - If bases differ: return random bit
    """
    if prepared_basis == measure_basis:
        return true_bit
    else:
        return int(rng.integers(0, 2))

def run_bb84(
    n_qubits: int = 1000,
    noise: float = 0.0,
    eve_present: bool = False,
    sample_rate: float = 0.2,
    threshold: float = 0.11,
    seed: Optional[int] = None,
) -> BB84Result:
    """
    Simulate the BB84 protocol (intercept-resend Eve if present).
    Returns a BB84Result with full run data.

    Args:
        n_qubits: number of qubits transmitted
        noise: probability that Bob's measured bit flips (symmetric channel noise)
        eve_present: if True, an intercept-resend eavesdropper is simulated
        sample_rate: fraction of sifted bits revealed publicly to estimate QBER
        threshold: if sample QBER > threshold, abort (typical security threshold ~11%)
        seed: RNG seed (int) for reproducibility; if None, random

    Notes:
        - In intercept-resend, Eve chooses random basis and measures each qubit, then resends
          a qubit encoded in her basis with the measurement outcome. This introduces ~25% QBER
          on the sifted key (when Bob's and Alice's bases match).
    """
    assert 0 <= noise <= 1, "noise must be in [0,1]"
    assert 0 < n_qubits, "n_qubits must be positive"
    assert 0 <= sample_rate < 1, "sample_rate in [0,1)"

    rng = _rng(seed)

    # 1) Alice chooses random bits and bases
    alice_bits = _random_bits(rng, n_qubits)
    alice_bases = _random_bits(rng, n_qubits)  # 0=Z, 1=X

    # 2) Eve (optional) intercept-resends
    if eve_present:
        eve_bases = _random_bits(rng, n_qubits)

        # Eve measures Alice's qubits
        eve_meas = np.empty(n_qubits, dtype=np.int8)
        for i in range(n_qubits):
            eve_meas[i] = _measure_with_basis(int(alice_bits[i]), int(alice_bases[i]), int(eve_bases[i]), rng)

        # Eve resends qubits encoded as (eve_meas, eve_bases)
        prepared_bits = eve_meas
        prepared_bases = eve_bases
    else:
        eve_bases = None
        prepared_bits = alice_bits
        prepared_bases = alice_bases

    # 3) Bob chooses random bases and measures
    bob_bases = _random_bits(rng, n_qubits)
    bob_bits = np.empty(n_qubits, dtype=np.int8)
    for i in range(n_qubits):
        bob_bits[i] = _measure_with_basis(int(prepared_bits[i]), int(prepared_bases[i]), int(bob_bases[i]), rng)

    # 4) Apply symmetric channel/measurement noise (flip with prob noise)
    if noise > 0:
        flips = rng.random(n_qubits) < noise
        bob_bits = np.bitwise_xor(bob_bits, flips.astype(np.int8))

    # 5) Basis sifting: keep indices where Alice and Bob used same basis
    sift_mask = (alice_bases == bob_bases)
    sifted_alice = alice_bits[sift_mask]
    sifted_bob = bob_bits[sift_mask]

    # 6) Compute QBER on full sifted key (not revealed in practice, but useful for reporting)
    if sifted_bob.size == 0:
        qber_full = 0.0
    else:
        qber_full = float(np.mean(sifted_alice != sifted_bob))

    # 7) Public sampling to estimate QBER
    m = sifted_bob.size
    k = int(np.floor(sample_rate * m))
    if k > 0:
        sample_indices = _rng(seed).choice(m, size=k, replace=False)  # choose k indices reproducibly wrt seed
        sample_qber = float(np.mean(sifted_alice[sample_indices] != sifted_bob[sample_indices]))
    else:
        sample_indices = np.array([], dtype=int)
        sample_qber = 0.0

    # 8) Abort or keep key (remove sampled bits from final key)
    aborted = False
    reason = ""
    if k == 0 and m == 0:
        aborted = True
        reason = "No sifted bits; increase n_qubits."
        final_key = np.array([], dtype=np.int8)
    elif sample_qber > threshold:
        aborted = True
        reason = f"High QBER detected (sample {sample_qber:.3f} > threshold {threshold:.3f}); aborting."
        final_key = np.array([], dtype=np.int8)
    else:
        # remove sample indices from the sifted key to form the secret key
        if k > 0:
            keep_mask = np.ones(m, dtype=bool)
            keep_mask[sample_indices] = False
            final_key = sifted_alice[keep_mask]  # use Alice's bits; Bob has reconciled
        else:
            final_key = sifted_alice.copy()

    return BB84Result(
        n_qubits=n_qubits,
        noise=noise,
        eve_present=eve_present,
        sample_rate=sample_rate,
        threshold=threshold,
        seed=seed,
        alice_bits=alice_bits,
        alice_bases=alice_bases,
        bob_bases=bob_bases,
        bob_bits=bob_bits,
        eve_bases=eve_bases,
        sift_mask=sift_mask,
        sifted_alice=sifted_alice,
        sifted_bob=sifted_bob,
        qber_full=qber_full,
        sample_indices=sample_indices,
        qber_sample=sample_qber,
        aborted=aborted,
        reason=reason,
        final_key=final_key,
    )

def bits_to_str(bits: np.ndarray, max_len: int = 128) -> str:
    s = ''.join(map(str, bits.tolist()))
    if len(s) > max_len:
        return s[:max_len] + '...'
    return s

def xor_bytes(msg: bytes, key_bits: np.ndarray) -> bytes:
    """
    One-time pad using key_bits (repeated/truncated).
    """
    if key_bits.size == 0:
        return b""
    key_bytes = np.packbits(key_bits, bitorder='big')
    # Repeat key bytes to match msg length
    repeated = (msg.__len__() + len(key_bytes) - 1) // len(key_bytes)
    expanded = (key_bytes.tobytes() * repeated)[:len(msg)]
    return bytes([m ^ k for m, k in zip(msg, expanded)])

def otp_encrypt(plaintext: str, key_bits: np.ndarray, encoding="utf-8") -> Tuple[bytes, bytes]:
    pt = plaintext.encode(encoding)
    ct = xor_bytes(pt, key_bits)
    return pt, ct

def otp_decrypt(ciphertext: bytes, key_bits: np.ndarray, encoding="utf-8") -> str:
    pt = xor_bytes(ciphertext, key_bits)
    return pt.decode(encoding, errors="replace")
