# app.py
import streamlit as st
import numpy as np

from bb84 import run_bb84, bits_to_str, otp_encrypt, otp_decrypt
from rsa_utils import (
    generate_keys,
    encode_msg_to_int,
    decode_int_to_msg,
    rsa_encrypt,
    rsa_decrypt,
    factor_n_trial,
)

st.set_page_config(page_title="BB84 QKD Simulator", page_icon="🔒", layout="wide")
st.set_page_config(page_title="Crypto Demo: RSA/ECC vs QKD", page_icon="🔐", layout="wide")

# ---- Session state init ----
# ---------------- Session State ----------------
if "bb84_res" not in st.session_state:
st.session_state.bb84_res = None
if "otp_ct_hex" not in st.session_state:
st.session_state.otp_ct_hex = ""
if "otp_dec" not in st.session_state:
st.session_state.otp_dec = ""

st.title("🔒 BB84 QKD Demonstration Simulator")
st.write("Configure the parameters, run the protocol, and see whether a secure key can be established.")

with st.sidebar:
    st.header("Parameters")
    n_qubits = st.slider("Number of qubits sent", 50, 5000, 1000, step=50)
    noise = st.slider("Channel noise (bit-flip prob.)", 0.0, 0.2, 0.02, step=0.01)
    eve_present = st.toggle("Eavesdropper (Eve) present?", value=False)
    sample_rate = st.slider("Public sample fraction", 0.0, 0.5, 0.2, step=0.05)
    threshold = st.slider("Abort threshold (QBER)", 0.01, 0.3, 0.11, step=0.01)
    seed = st.number_input("Seed (reproducible)", min_value=0, value=42)

    # Primary action
    if st.button("Run BB84", use_container_width=True):
        st.session_state.bb84_res = run_bb84(
            n_qubits=n_qubits,
            noise=noise,
            eve_present=eve_present,
            sample_rate=sample_rate,
            threshold=threshold,
            seed=int(seed),
if "rsa_keys" not in st.session_state:
    st.session_state.rsa_keys = None
if "rsa_cipher" not in st.session_state:
    st.session_state.rsa_cipher = None
if "rsa_plain_out" not in st.session_state:
    st.session_state.rsa_plain_out = ""

# ---------------- Header ----------------
st.title("🔐 Classical vs Quantum Key Exchange — Live Demo")
st.caption(
    "Left: classical RSA demo (tiny keys for illustration). Right: BB84 QKD simulator. "
    "Toggle **Eve** to see what an attacker can do in each world."
)

mode = st.radio("Choose a view:", ["Side-by-side (RSA + QKD)", "Only QKD (BB84)", "Only RSA (toy)"], horizontal=True)
attacker = st.toggle(
    "Eve (attacker) ON?",
    value=False,
    help="In RSA toy demo, Eve factors tiny n. In QKD, Eve performs intercept–resend, raising QBER."
)

# ---------------- RSA Panel ----------------
def rsa_panel():
    with st.container():
        st.subheader("🔓 Classical (RSA) — Toy Demo")
        st.write(
            "This uses *tiny* RSA keys for a **teaching demo**. Real RSA uses 2048+ bits. "
            "Here, if Eve is ON, she factors `n` quickly and recovers the plaintext."
)
        # clear previous OTP outputs
        st.session_state.otp_ct_hex = ""
        st.session_state.otp_dec = ""

# Always read result from session_state (persists across reruns)
res = st.session_state.bb84_res
        cols = st.columns(2)

if res is None:
    st.info("Configure parameters in the sidebar and click **Run BB84**.")
else:
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Raw bits (sent)", res.n_qubits)
        st.metric("Sifted bits (kept)", int(res.sifted_alice.size))
    with col2:
        st.metric("QBER (full sifted)", f"{100*res.qber_full:.2f}%")
        st.metric("QBER (public sample)", f"{100*res.qber_sample:.2f}%")
    with col3:
        if res.aborted:
            st.error("Key Aborted")
            st.write(res.reason)
            st.metric("Final key length", 0)
        # Left controls / encryption
        with cols[0]:
            bits = st.slider("Bits per prime (toy)", 12, 20, 16, help="Smaller → easier to factor (for the demo).")
            msg = st.text_input("Message", "hello quantum world")

            if st.button("Generate RSA keys & Encrypt", key="rsa_gen"):
                # Generate small RSA keys
                keys = generate_keys(bits_per_prime=bits)
                st.session_state.rsa_keys = keys

                # Encode message; ensure it fits under n
                m = encode_msg_to_int(msg)
                max_len = (keys.n.bit_length() - 1) // 8  # rough bytes limit for m < n
                msg_bytes = msg.encode("utf-8")
                if len(msg_bytes) >= max_len:
                    msg_bytes = msg_bytes[: max_len - 1] if max_len > 1 else b"A"
                    m = int.from_bytes(msg_bytes, "big")

                # Encrypt
                c = rsa_encrypt(m, keys.n, keys.e)
                st.session_state.rsa_cipher = c
                st.session_state.rsa_plain_out = ""

            if st.session_state.rsa_keys and st.session_state.rsa_cipher is not None:
                k = st.session_state.rsa_keys
                st.code(f"Public key (n, e):\n n = {k.n}\n e = {k.e}")
                st.code(f"Ciphertext (int): {st.session_state.rsa_cipher}")

        # Right: receiver / attacker
        with cols[1]:
            if st.session_state.rsa_keys and st.session_state.rsa_cipher is not None:
                k = st.session_state.rsa_keys

                if attacker:
                    st.warning("Eve is ON → factoring n via trial division (toy).")
                    p, q = factor_n_trial(k.n)
                    if p and q:
                        st.code(f"Eve factored n: p = {p}, q = {q}")
                        phi = (p - 1) * (q - 1)

                        # Recompute d = e^{-1} mod phi quickly (inline)
                        def egcd(a, b):
                            if b == 0:
                                return a, 1, 0
                            g, y, x = egcd(b, a % b)
                            return g, x, y - (a // b) * x

                        def modinv(a, m):
                            g, x, _ = egcd(a, m)
                            return x % m if g == 1 else None

                        d_eve = modinv(k.e, phi)
                        if d_eve is not None:
                            m_eve = rsa_decrypt(st.session_state.rsa_cipher, k.n, d_eve)
                            st.session_state.rsa_plain_out = decode_int_to_msg(m_eve)
                            st.success("Eve recovered the plaintext")
                            st.code(st.session_state.rsa_plain_out)
                        else:
                            st.error("Could not invert e modulo phi (unexpected in demo).")
                    else:
                        st.error("Factoring failed (choose fewer bits).")
                else:
                    st.info("Eve OFF → only the intended receiver (with private key) can decrypt (in this toy).")
                    m_recv = rsa_decrypt(st.session_state.rsa_cipher, k.n, k.d)
                    st.session_state.rsa_plain_out = decode_int_to_msg(m_recv)
                    st.code("Receiver decrypted message:")
                    st.code(st.session_state.rsa_plain_out)

        st.caption(
            "⚠️ Educational demo only: tiny keys, no padding. Real RSA (2048+ bits) is safe *today* against classical attackers, "
            "but **Shor's algorithm on a sufficiently large quantum computer would break it.**"
        )

# ---------------- QKD Panel ----------------
def qkd_panel():
    with st.container():
        st.subheader("🔒 Quantum (BB84) — Key Distribution")

        left, right = st.columns(2)
        with left:
            n_qubits = st.slider("Number of qubits", 50, 5000, 1000, step=50, key="q_n")
            noise = st.slider("Channel noise (bit-flip prob.)", 0.0, 0.2, 0.02, step=0.01, key="q_noise")
            sample_rate = st.slider("Public sample fraction", 0.0, 0.5, 0.2, step=0.05, key="q_sample")
            threshold = st.slider("Abort threshold (QBER)", 0.01, 0.3, 0.11, step=0.01, key="q_thr")
            seed = st.number_input("Seed (reproducible)", min_value=0, value=42, key="q_seed")

            if st.button("Run BB84", key="bb84_run"):
                st.session_state.bb84_res = run_bb84(
                    n_qubits=n_qubits,
                    noise=noise,
                    eve_present=attacker,   # Eve toggle controls intercept–resend
                    sample_rate=sample_rate,
                    threshold=threshold,
                    seed=int(seed),
                )
                # Clear previous OTP outputs
                st.session_state.otp_ct_hex = ""
                st.session_state.otp_dec = ""

        res = st.session_state.bb84_res

        with right:
            if res is None:
                st.info("Click **Run BB84** to simulate. Toggle Eve to see error jump.")
            else:
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.metric("Raw bits (sent)", res.n_qubits)
                    st.metric("Sifted bits (kept)", int(res.sifted_alice.size))
                with c2:
                    st.metric("QBER (full sifted)", f"{100*res.qber_full:.2f}%")
                    st.metric("QBER (public sample)", f"{100*res.qber_sample:.2f}%")
                with c3:
                    if res.aborted:
                        st.error("Key Aborted")
                        st.write(res.reason)
                        st.metric("Final key length", 0)
                    else:
                        st.success("Key Established ✅")
                        st.metric("Final key length", int(res.final_key.size))

                with st.expander("Show raw & sifted data (truncated)"):
                    st.code(f"Alice bases (0=Z,1=X): {bits_to_str(res.alice_bases, 256)}")
                    st.code(f"Alice bits:           {bits_to_str(res.alice_bits, 256)}")
                    st.code(f"Bob bases:            {bits_to_str(res.bob_bases, 256)}")
                    st.code(f"Bob bits:             {bits_to_str(res.bob_bits, 256)}")
                    st.code(f"Sift mask:            {bits_to_str(res.sift_mask.astype(int), 256)}")
                    st.code(f"Sifted Alice:         {bits_to_str(res.sifted_alice, 256)}")
                    st.code(f"Sifted Bob:           {bits_to_str(res.sifted_bob, 256)}")

        st.divider()
        st.subheader("One-Time Pad (with BB84 key)")
        if res is None:
            st.info("Run BB84 first to establish a key.")
else:
            st.success("Key Established ✅")
            st.metric("Final key length", int(res.final_key.size))

    with st.expander("Show raw & sifted data (truncated)"):
        st.code(f"Alice bases (0=Z,1=X): {bits_to_str(res.alice_bases, 256)}")
        st.code(f"Alice bits:           {bits_to_str(res.alice_bits, 256)}")
        st.code(f"Bob bases:            {bits_to_str(res.bob_bases, 256)}")
        st.code(f"Bob bits:             {bits_to_str(res.bob_bits, 256)}")
        st.code(f"Sift mask:            {bits_to_str(res.sift_mask.astype(int), 256)}")
        st.code(f"Sifted Alice:         {bits_to_str(res.sifted_alice, 256)}")
        st.code(f"Sifted Bob:           {bits_to_str(res.sifted_bob, 256)}")
        if res.eve_present and res.eve_bases is not None:
            st.code(f"Eve bases:            {bits_to_str(res.eve_bases, 256)}")

    st.divider()
    st.header("One-Time Pad Demo")

    # OTP section uses session_state to persist outputs too
    pt = st.text_input("Message to encrypt", "hello quantum world")
    btn_disabled = (res.aborted or res.final_key.size == 0)

    if st.button("Encrypt & Decrypt with Current Key", disabled=btn_disabled):
        # Perform OTP using the saved result
        _, ct = otp_encrypt(pt, res.final_key)
        st.session_state.otp_ct_hex = ct.hex()
        st.session_state.otp_dec = otp_decrypt(ct, res.final_key)

    if st.session_state.otp_ct_hex:
        st.write("Ciphertext (hex):")
        st.code(st.session_state.otp_ct_hex)
        st.write("Decrypted plaintext:")
        st.code(st.session_state.otp_dec)
            pt = st.text_input("Message", "hello quantum world", key="q_msg")
            btn_disabled = (res.aborted or res.final_key.size == 0)
            if st.button("Encrypt & Decrypt with Current Key", disabled=btn_disabled, key="q_otp"):
                _, ct = otp_encrypt(pt, res.final_key)
                st.session_state.otp_ct_hex = ct.hex()
                st.session_state.otp_dec = otp_decrypt(ct, res.final_key)

            if st.session_state.otp_ct_hex:
                st.write("Ciphertext (hex):")
                st.code(st.session_state.otp_ct_hex)
                st.write("Decrypted plaintext:")
                st.code(st.session_state.otp_dec)

# ---------------- Layout ----------------
if mode == "Only RSA (toy)":
    rsa_panel()
elif mode == "Only QKD (BB84)":
    qkd_panel()
else:
    colA, colB = st.columns(2)
    with colA:
        rsa_panel()
    with colB:
        qkd_panel()

st.caption(
    "Demo for education: RSA panel uses tiny keys to illustrate factoring. "
    "QKD panel simulates BB84; no real quantum hardware."
)