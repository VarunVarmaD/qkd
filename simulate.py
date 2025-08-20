\
"""
Simple CLI to run a BB84 simulation without the UI.

Usage:
    python simulate.py --n 1000 --noise 0.02 --eve 0 --sample 0.2 --thr 0.11 --seed 42
"""
import argparse
from bb84 import run_bb84, bits_to_str

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=1000, help="number of qubits")
    parser.add_argument("--noise", type=float, default=0.02, help="channel noise flip prob")
    parser.add_argument("--eve", type=int, default=0, help="1 to enable intercept-resend Eve")
    parser.add_argument("--sample", type=float, default=0.2, help="public sample fraction")
    parser.add_argument("--thr", type=float, default=0.11, help="abort threshold QBER")
    parser.add_argument("--seed", type=int, default=42, help="rng seed")
    args = parser.parse_args()

    res = run_bb84(
        n_qubits=args.n,
        noise=args.noise,
        eve_present=bool(args.eve),
        sample_rate=args.sample,
        threshold=args.thr,
        seed=args.seed,
    )

    print(f"Sifted bits: {res.sifted_alice.size}")
    print(f"QBER (full): {100*res.qber_full:.2f}%")
    print(f"QBER (sample): {100*res.qber_sample:.2f}%")
    print("Aborted:", res.aborted, res.reason)
    print("Final key length:", res.final_key.size)
    print("Final key preview:", bits_to_str(res.final_key, 128))

if __name__ == "__main__":
    main()
